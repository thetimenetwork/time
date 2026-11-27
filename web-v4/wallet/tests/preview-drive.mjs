// Drives a headless Chrome, with a new empty profile, through the wallet's screens on preview-server.mjs: takes a
// screenshot of each screen, and walks the paths of campaign/lib/browser-check.mjs that the mock chain can carry, with
// the same selectors in the same order. Nothing here touches a network; see preview-server.mjs for what it proves
// (nothing about the wallet's checks) and what it shows (the pages, their layout, their wiring, their CSP).
//
//   node web-v4/wallet/tests/preview-server.mjs &
//   node web-v4/wallet/tests/preview-drive.mjs [--out DIR] [--chrome PATH] [--widths 390,1280] [--theme light|dark] [--only screens,flows,alerts,busy,market]
//
// DIR receives NNNN-name.png per screen and width, and log.txt: each step with ok or FAIL, and what the pages complained of.
import { launchChrome, createBrowser } from '../../../campaign/lib/browser-check.mjs';
import { copyFile, mkdir, readdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const argument = (name, fallback) => { const at = process.argv.indexOf(name); return at < 0 ? fallback : process.argv[at + 1]; };
const out = path.resolve(argument('--out', path.join(os.tmpdir(), `time-wallet-preview-${Date.now()}`)));
const widths = argument('--widths', '390,1280').split(',').map(Number), theme = argument('--theme', 'light'), only = new Set(argument('--only', 'screens,flows,alerts').split(','));
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
/// What the step of the recovery words shows (papers.mjs): how many words, whether a sheet is anywhere in the page, how
/// many things in the step can be downloaded or printed, whether the tip and the button that goes on are shown, the
/// height of the buttons, and whether anything is wider than the screen.
const wordsStep = (page, prefix) => browser.ask(page, `(() => { const q = (id) => document.getElementById('${prefix}-' + id), seen = (e) => Boolean(e) && e.getClientRects().length > 0, step = q('sheet-step'), height = (id) => Math.round(q(id).getBoundingClientRect().height); return { words: q('phrase-shown').textContent.trim().split(/\\s+/).length, sheet_in_page: /([0-9A-HJKMNP-TV-Z]{4} ){13}[0-9A-HJKMNP-TV-Z]{4}/.test(document.documentElement.textContent), to_save: [...step.querySelectorAll('[id*="kit"], [id$="-print"]')].filter(seen).length, tip: seen(q('tip')), submit_shown: seen(q('submit')), buttons: { submit: height('submit'), cancel: height('cancel') }, wide: document.documentElement.scrollWidth > window.innerWidth }; })()`);
const wordsLook = (s) => !s.wide && s.tip && s.submit_shown && s.buttons.submit >= 52 && s.buttons.cancel >= 52;
/// What the kit step of "New recovery words" shows with "Words and a Recovery Kit": how many words, whether a sheet is
/// anywhere in the page, whether the way on is offered, the height of its buttons, and whether anything is too wide.
const kitStep = (page, prefix) => browser.ask(page, `(() => { const q = (id) => document.getElementById('${prefix}-' + id), height = (id) => Math.round(q(id).getBoundingClientRect().height); return { words: q('phrase-shown').textContent.trim().split(/\\s+/).length, sheet_in_page: /([0-9A-HJKMNP-TV-Z]{4} ){13}[0-9A-HJKMNP-TV-Z]{4}/.test(document.documentElement.textContent), submit_hidden: q('submit').hidden, buttons: { download: height('kit-download'), print: height('print'), cancel: height('cancel'), submit: q('submit').hidden ? 0 : height('submit') }, wide: document.documentElement.scrollWidth > window.innerWidth }; })()`);
const kitLooks = (kit) => !kit.wide && [kit.buttons.download, kit.buttons.print, kit.buttons.cancel].every((h) => h >= 52) && (kit.submit_hidden || kit.buttons.submit >= 52);
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
  // The page that never starts (boot-check.js): app.js, then the stylesheet, answer 404 (preview-server.mjs, /__break).
  await step(`screens ${width}: the page that never starts`, async () => {
    const page = await browser.open(W + '/'); pages.push(page); await look(page, width);
    try {
      for (const [file, name] of [['app.js', '00-boot-failed'], ['styles.css', '00b-boot-failed-no-style']]) {
        await browser.ask(page, `fetch('/__break?file=${file}').then(() => true)`);
        await browser.go(page, W + '/');
        await until(page, `document.querySelector('#boot-failed').getClientRects().length > 0`, `the message when ${file} does not load`, 30000);
        const seen = await browser.ask(page, `({ says: document.querySelector('#boot-failed').innerText.replace(/\\s+/g, ' ').trim(), others: [...document.querySelectorAll('main > *')].filter(e => e.id !== 'boot-failed' && e.getClientRects().length > 0).length, button: Math.round(document.querySelector('#boot-reload').getBoundingClientRect().height), wide: document.documentElement.scrollWidth > window.innerWidth })`);
        expect(seen.says === 'The wallet could not load. Check your connection and reload this page. Nothing was changed. Reload' && !seen.wide && (file !== 'app.js' || (seen.others === 0 && seen.button >= 44)), `${file}: ${JSON.stringify(seen)}`);
        await shot(page, name, width);
      }
    } finally { await browser.ask(page, `fetch('/__break?file=').then(() => true)`); }
  });
  // The step of the recovery words at a protected sign-up (signup-ui.mjs, papers.mjs), on a mock network that takes such
  // accounts (preview-server.mjs, /__protect). Nothing is registered: the mock chain cannot.
  await step(`screens ${width}: the recovery words at a protected sign-up, and the recover panel`, async () => {
    const page = await opened(null, width);
    await browser.ask(page, `fetch('/__protect?on=1').then(() => true)`);
    try {
      await browser.go(page, W + '/'); await until(page, `!document.querySelector('#auth-submit').disabled && document.querySelector('#signup-protected').getClientRects().length > 0`, 'the protected form');
      await shot(page, '05-signup-protected-form', width, { full: true });
      await browser.fill(page, 'username', 'dora'); await browser.fill(page, 'password', PASSWORD); await browser.fill(page, 'password-confirm', PASSWORD);
      await browser.fill(page, 'signup-payment', PAYMENT); await browser.fill(page, 'signup-payment-confirm', PAYMENT);
      await browser.click(page, '#auth-submit');
      await until(page, `!document.querySelector('#signup-sheet-step').hidden && document.querySelector('#signup-phrase-shown').textContent.length > 20`, 'the step of the recovery words', 240000);
      const shown = await wordsStep(page, 'signup');
      expect(shown.words === 5 && !shown.sheet_in_page && shown.to_save === 0 && wordsLook(shown), `the step of the recovery words: ${JSON.stringify(shown)}`);
      await shot(page, '06-signup-words', width, { full: true });
      await browser.click(page, '#signup-cancel');
      // "Recover my account" on the start screen: the name and the words first; a kit only under its own heading.
      await browser.ask(page, `(document.querySelector('#way-sheet').open = true, true)`);
      await browser.click(page, '#lost-open'); await until(page, `!document.querySelector('#security-recover-panel').hidden`, 'the recover panel');
      await shot(page, '09-recover-panel', width, { full: true });
      // With carol's kit chosen: the panel reads it at once and fills her name.
      const downloads = path.join(out, 'downloads', String(width)); await mkdir(downloads, { recursive: true });
      const kitFile = path.join(downloads, `time-recovery-kit-carol-${'c6'.repeat(4)}.json`);
      await writeFile(kitFile, await browser.ask(page, `fetch('/__papers').then(r => r.json()).then(p => p.kit)`));
      await browser.fill(page, 'lost-name', '');
      await browser.ask(page, `(document.querySelector('#lost-kit').open = true, true)`);
      const root = await cdp.send('DOM.getDocument', { depth: 0 }, page.sessionId), input = await cdp.send('DOM.querySelector', { nodeId: root.root.nodeId, selector: '#lost-file' }, page.sessionId);
      await cdp.send('DOM.setFileInputFiles', { files: [kitFile], nodeId: input.nodeId }, page.sessionId);
      await until(page, `document.querySelector('#lost-file-status').textContent === 'This is the Recovery Kit of @carol.'`, 'the panel reads the kit');
      const panel = await browser.ask(page, `({ name: document.querySelector('#lost-name').value, wide: document.documentElement.scrollWidth > window.innerWidth })`);
      expect(panel.name === 'carol' && !panel.wide, `the recover panel with the kit: ${JSON.stringify(panel)}`);
      await shot(page, '10-recover-panel-kit', width, { full: true });
      await browser.click(page, '#lost-close');
      return { shown, panel };
    } finally { await browser.ask(page, `fetch('/__protect?on=0').then(() => true)`); }
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
    // "Show my recovery words": the step of the recovery words in "Protect my account", then "Start over".
    for (const [id, value] of [['secure-login', 'harbor lantern login words 1'], ['secure-login-confirm', 'harbor lantern login words 1'], ['secure-payment', 'copper meadow pay words 22'], ['secure-payment-confirm', 'copper meadow pay words 22']]) await browser.fill(page, id, value);
    await browser.click(page, '#secure-form button[type=submit]');
    await until(page, `!document.querySelector('#secure-sheet-step').hidden && document.querySelector('#secure-phrase-shown').textContent.length > 20`, 'the step of the recovery words', 240000);
    const shown = await wordsStep(page, 'secure');
    expect(shown.words === 5 && !shown.sheet_in_page && shown.to_save === 0 && wordsLook(shown), `the step of the recovery words: ${JSON.stringify(shown)}`);
    await shot(page, '22-keys-protect-words', width, { full: true });
    await browser.click(page, '#secure-cancel');
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
    await browser.ask(page, `Promise.all([fetch('/__seed?s=words-only').then(r => r.json()).then(o => { for (const [k, v] of Object.entries(o)) localStorage.setItem(k, v); }), fetch('/__rich?on=1')]).then(() => true)`);
    await browser.ask(page, `(document.querySelector('#refresh').click(), true)`); await until(page, `Boolean(document.querySelector('#keys-add-kit'))`, 'the quiet line on the card of the words');
    await shot(page, '41b-keys-one-paper', width, { full: true });
    await browser.click(page, '#keys-add-kit');
    const offered = await browser.ask(page, `({ open: document.querySelector('#keys-change').open, kit: document.querySelector('#rr-kind-kit').checked, words: document.querySelector('#rr-kind-words').checked })`);
    expect(offered.open && offered.kit && !offered.words, `the line leads to "New recovery words" with a kit: ${JSON.stringify(offered)}`);
    await until(page, `Math.abs(document.querySelector('#rr-card').getBoundingClientRect().top) < 160`, '"New recovery words" in view');
    await shot(page, '41c-keys-add-kit', width);
    await browser.click(page, '#rr-kind-words'); await browser.ask(page, `(document.querySelector('#keys-change').open = false, true)`);
    await browser.ask(page, `fetch('/__rich?on=0').then(() => { localStorage.removeItem(Object.keys(localStorage).find(k => k.startsWith('timecurrency.recovery-kind.v1:'))); return true; })`);
    await browser.ask(page, `(document.querySelector('#refresh').click(), true)`); await until(page, `!document.querySelector('#keys-add-kit')`, 'no line without the marker');
    await browser.ask(page, `(document.querySelector('#keys-change').open = true)`); await shot(page, '42-keys-change', width, { full: true });
    // "New recovery words": words only (selected at first), then with a Recovery Kit; each with the approval under it,
    // then "Discard".
    await browser.click(page, '#rr-start');
    await until(page, `!document.querySelector('#rr-sheet-step').hidden && document.querySelector('#rr-phrase-shown').textContent.length > 20`, 'the step of the new recovery words', 240000);
    const rrWords = await wordsStep(page, 'rr');
    expect(rrWords.words === 5 && !rrWords.sheet_in_page && rrWords.to_save === 0 && wordsLook(rrWords), `the step of the new recovery words: ${JSON.stringify(rrWords)}`);
    await shot(page, '42b-keys-new-words', width, { full: true });
    await browser.click(page, '#rr-cancel');
    await browser.click(page, '#rr-kind-kit'); await browser.click(page, '#rr-start');
    await until(page, `!document.querySelector('#rr-sheet-step').hidden && document.querySelector('#rr-phrase-shown').textContent.length > 20 && !document.querySelector('#rr-with-kit').hidden`, 'the step of the new Recovery Kit', 240000);
    const rrKit = await kitStep(page, 'rr');
    expect(rrKit.words === 5 && !rrKit.sheet_in_page && rrKit.submit_hidden && kitLooks(rrKit), `the step of the new Recovery Kit: ${JSON.stringify(rrKit)}`);
    await shot(page, '42c-keys-new-words-kit', width, { full: true });
    await browser.click(page, '#rr-cancel'); await browser.click(page, '#rr-kind-words');
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
    // A request in no form the wallet takes (web audit, W-1): one fixed sentence, nothing of the website's words.
    await cdp.send('Target.closeTarget', { targetId: popup.targetId }); await delay(300);
    await browser.click(shop, '#odd');
    const odd = await browser.opened(shop, W + '/approve'); pages.push(odd); await look(odd, small);
    await until(odd, `!document.querySelector('#auth-submit').disabled`, 'the window is ready');
    await until(odd, `document.querySelector('#approval-title').textContent === 'Request not understood'`, 'the fixed sentence', 60000);
    const said = await browser.ask(odd, `({ details: document.querySelector('#approval-details').textContent, notice: document.querySelector('#notice').textContent, approve: document.querySelector('#approve-request').disabled, page: document.body.innerText })`);
    expect(said.details === 'This website sent a request the wallet does not understand. Nothing was shown or signed.' && said.approve && !said.page.includes('SECURITY CHECK'), JSON.stringify(said).slice(0, 300));
    await shot(odd, '54-website-not-understood', small, { full: true });
    return { website_says: (await browser.text(shop, '#out')).slice(0, 80) };
  });
}

// The Alerts panel at the top of Home (alerts-ui.mjs) for carol: nothing to see, a payment that waits, a replacement of
// her keys asked with her recovery words (each arriving by the hint, with nothing pressed), "I have seen these", and
// the start screen and the locked wallet without any of it. Then the switch in each state a browser can be in, each in
// a page of its own (the page asks the alert service once): no service, a service and alerts off, "Turn on alerts"
// pressed in this headless Chrome (it has no push service: the wallet is to say it failed), on, an iPhone outside the
// Home Screen, and notifications blocked with no hint route. "On" needs a push subscription, which a headless Chrome
// cannot make: for that picture only, the page is given a stand-in one before its scripts run.
if (only.has('alerts')) for (const width of widths) {
  const panel = (page) => browser.ask(page, `(() => { const q = (s) => document.querySelector(s), seen = (s) => q(s).getClientRects().length > 0; return { banner: seen('#alerts-banner') ? q('#alerts-banner').textContent : null, panel: seen('#alerts-panel'), titles: [...q('#alerts-list').children].map((li) => li.querySelector('strong').firstChild.textContent), none: seen('#alerts-none'), confirm: seen('#alerts-confirm'), live: q('#alerts-live').textContent, state: q('#alerts-switch-state').textContent, why: seen('#alerts-switch-why') ? q('#alerts-switch-why').textContent : '', buttons: ['alerts-turn-on', 'alerts-turn-off', 'alerts-off-everywhere'].filter((id) => seen('#' + id)), wide: document.documentElement.scrollWidth > window.innerWidth }; })()`);
  const server = (page, ...routes) => browser.ask(page, `Promise.all(${JSON.stringify(routes)}.map((u) => fetch(u))).then(() => true)`);
  const settled = (page) => until(page, `document.querySelector('#alerts-live').textContent !== '' && document.querySelector('#alerts-switch-state').textContent !== ''`, 'the panel and its switch');
  await step(`alerts ${width}: the panel, live, and "I have seen these"`, async () => {
    const page = await opened('protected', width); await server(page, '/__reset', '/__alerts-state?s=none', '/__alerts?mode=off', '/__touches?on=1');
    const start = await panel(page);
    expect(start.banner === null && !start.panel, `the start screen shows the alerts: ${JSON.stringify(start)}`);
    await unlock(page, 'carol'); await settled(page);
    await until(page, `document.querySelector('#alerts-live').textContent === 'Watching live'`, 'the panel watches live');
    const none = await panel(page);
    expect(none.panel && none.none && none.titles.length === 0 && none.banner === null && !none.confirm && !none.wide, JSON.stringify(none));
    await shot(page, '70-alerts-none', width);
    await server(page, '/__alerts-state?s=payment');
    await until(page, `document.querySelector('#alerts-banner').textContent === 'A payment is waiting'`, 'the waiting payment, by the hint', 10000);
    const payment = await panel(page);
    expect(payment.confirm && payment.titles[0] === 'A payment is waiting' && !payment.wide, JSON.stringify(payment));
    await shot(page, '71-alerts-payment', width);
    await server(page, '/__alerts-state?s=takeover');
    await until(page, `document.querySelector('#alerts-banner').textContent === 'Your keys are being replaced'`, 'the replacement of the keys, by the hint', 10000);
    const takeover = await panel(page);
    expect(takeover.titles[0] === 'Your keys are being replaced' && !takeover.wide, JSON.stringify(takeover));
    await shot(page, '72-alerts-takeover', width, { full: true });
    await browser.click(page, '#alerts-confirm');
    const seen = await panel(page);
    expect(seen.banner === null && !seen.confirm && seen.titles.includes('Your keys are being replaced'), JSON.stringify(seen));
    await shot(page, '73-alerts-seen', width);
    await server(page, '/__alerts-state?s=none');
    await browser.click(page, '#lock-button'); await until(page, `document.querySelector('#dashboard').hidden`, 'locked');
    const locked = await panel(page);
    expect(locked.banner === null && !locked.panel && locked.titles.length === 0, `the locked wallet shows the alerts: ${JSON.stringify(locked)}`);
    return { none: none.state, payment: payment.titles, takeover: takeover.titles, seen: seen.titles };
  });
  await step(`alerts ${width}: the switch in each state`, async () => {
    const states = {};
    const fresh = async ({ routes = [], before = null } = {}) => {
      const page = await browser.open('about:blank'); pages.push(page); await look(page, width);
      if (before) await before(page);
      await browser.go(page, W + '/'); await until(page, `!document.querySelector('#auth-submit').disabled`, 'the wallet is ready');
      await browser.ask(page, `fetch('/__seed?s=protected').then(r => r.json()).then(o => { for (const [k, v] of Object.entries(o)) localStorage.setItem(k, v); return true; })`);
      await server(page, '/__reset', '/__alerts-state?s=none', '/__alerts?mode=off', '/__touches?on=1', ...routes);
      await browser.go(page, W + '/'); await until(page, `!document.querySelector('#auth-submit').disabled`, 'the wallet is ready again');
      await unlock(page, 'carol'); await settled(page); await delay(300);
      return page;
    };
    // No alert service here (a lab gateway).
    let page = await fresh(); states.none = await panel(page);
    expect(states.none.state === 'Alerts are off for this browser.' && states.none.why === 'This wallet\'s service does not send alerts.' && states.none.buttons.length === 0, JSON.stringify(states.none));
    // A service, alerts off: why they matter, and the buttons.
    page = await fresh({ routes: ['/__alerts?mode=offered'] }); states.offered = await panel(page);
    expect(states.offered.state.startsWith('Alerts are off for this browser. Turn them on') && states.offered.buttons.join() === 'alerts-turn-on,alerts-off-everywhere' && !states.offered.wide, JSON.stringify(states.offered));
    await shot(page, '74-alerts-switch-offered', width, { full: true });
    // "Turn on alerts" pressed with notifications allowed, in a browser without a push service of its own.
    await cdp.send('Browser.grantPermissions', { permissions: ['notifications'], origin: W, browserContextId: page.browserContextId });
    await browser.click(page, '#alerts-turn-on');
    const said = await until(page, `(() => { const n = document.querySelector('#notice'); return n && !n.hidden && !n.className.includes('busy') && n.textContent !== 'Preparing your request…' ? { text: n.textContent, error: n.className.includes('error') } : null; })()`, 'the wallet says how turning on went', 60000);
    states.pressed = { said, ...(await panel(page)) };
    expect(states.pressed.state !== 'Alerts are on for this browser.' || !said.error, JSON.stringify(states.pressed));
    await shot(page, '75-alerts-turn-on-headless', width);
    // On: a stand-in subscription, and this browser's record of it for carol.
    page = await fresh({ routes: ['/__alerts?mode=offered'], before: async (p) => {
      await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `(() => { const sub = { endpoint: 'https://push.example/preview', unsubscribe: async () => true }; const reg = { pushManager: { getSubscription: async () => sub } }; ServiceWorkerContainer.prototype.getRegistration = async function () { return reg; }; localStorage.setItem('timecurrency.alerts-push.v1:' + 'c6'.repeat(32) + ':7', sub.endpoint); })();` }, p.sessionId);
    } });
    states.on = await panel(page);
    expect(states.on.state === 'Alerts are on for this browser.' && states.on.buttons.join() === 'alerts-turn-off,alerts-off-everywhere', JSON.stringify(states.on));
    await shot(page, '76-alerts-switch-on', width, { full: true });
    // An iPhone outside the Home Screen.
    page = await fresh({ routes: ['/__alerts?mode=offered'], before: (p) => cdp.send('Emulation.setUserAgentOverride', { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', platform: 'iPhone' }, p.sessionId) });
    states.iphone = await panel(page);
    expect(states.iphone.why.startsWith('On an iPhone or iPad, alerts work only from the Home Screen.') && states.iphone.buttons.length === 0, JSON.stringify(states.iphone));
    await shot(page, '77-alerts-switch-iphone', width);
    // Notifications blocked, and no hint route: the status says when it checked.
    page = await fresh({ routes: ['/__alerts?mode=offered', '/__touches?on=0'], before: (p) => cdp.send('Browser.setPermission', { permission: { name: 'notifications' }, setting: 'denied', origin: W, browserContextId: p.browserContextId }) });
    await until(page, `document.querySelector('#alerts-live').textContent === 'Checked a moment ago'`, 'without the hint the panel says when it checked');
    states.denied = await panel(page);
    expect(states.denied.why.startsWith('Notifications are blocked for this wallet') && states.denied.live === 'Checked a moment ago', JSON.stringify(states.denied));
    await shot(page, '78-alerts-switch-denied-no-hint', width);
    await server(page, '/__alerts?mode=off', '/__touches?on=1');
    return Object.fromEntries(Object.entries(states).map(([k, v]) => [k, { state: v.state.slice(0, 60), why: v.why.slice(0, 60), buttons: v.buttons, ...(v.said ? { said: v.said.text.slice(0, 80) } : {}) }]));
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
    await until(alice, `(!document.querySelector('#secure-sheet-step').hidden && document.querySelector('#secure-phrase-shown').textContent.length > 20)`, 'the step of the recovery words', 240000);
    // As campaign/lib/browser-check.mjs takes it: the words read, and "I wrote them down. Review and protect".
    const shown = await wordsStep(alice, 'secure');
    expect(shown.words === 5 && !shown.sheet_in_page && shown.to_save === 0 && shown.submit_shown, `the step of the recovery words: ${JSON.stringify(shown)}`);
    await browser.click(alice, '#secure-submit'); await until(alice, `document.querySelector('#review-dialog').open === true`, 'the review');
    const title = await browser.text(alice, '#review-title'); await browser.ask(alice, `(document.querySelector('#review-dialog').close('cancel'), true)`);
    expect(title === 'Protect my account', title);
    await browser.click(alice, '#secure-cancel');
    return { words: shown.words };
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
    expect(off.still_on === true && off.asks_for.includes('Payment password') && off.asks_for.includes('Recovery words'), JSON.stringify(off));
    // And the freeze is ended with the payment password and the recovery sheet.
    await browser.fill(carol, 'unfreeze-payment', PAYMENT); await browser.fill(carol, 'unfreeze-secret', sheet); await browser.click(carol, '#unfreeze-form button[type=submit]');
    await confirmReview('Unfreeze account'); await notice(carol, 'Your account is no longer frozen', 'the freeze has ended', 120000);
    card = await cardOf();
    expect(!card.freeze_on && card.status === 'Your account is protected.', JSON.stringify(card));
    await browser.ask(carol, `fetch('/__reset').then(() => true)`);
    return { paused_note: pause.body.replace(/\s+/g, ' ').slice(0, 160), ways: ways.wait_note, switches };
  });
  // The step "recovery-words" of campaign/lib/browser-check.mjs, with its selectors in its order: erin is words only, and
  // a browser that never saw her account recovers it with her name and her words alone, up to the review, cancelled.
  // carol also has a Recovery Kit: her words alone are not enough, and the panel says so.
  await step('flow: a words-only account in a fresh browser, with the name and the words, up to the review of a recovery (cancelled); an account with a kit is told it needs it', async () => {
    const { erinWords, words } = await browser.ask(alice, `fetch('/__papers').then(r => r.json())`);
    const stranger = await opened(null);
    await browser.ask(stranger, `(document.querySelector('#way-sheet').open = true, true)`);
    await browser.click(stranger, '#lost-open');
    await until(stranger, `document.querySelector('#lost-form').getClientRects().length > 0`, 'the recover panel opens');
    const fill = async (name, typed) => { await browser.fill(stranger, 'lost-name', name); await browser.fill(stranger, 'lost-phrase', typed); for (const [id, value] of [['lost-login', 'river stone login words 31'], ['lost-login-confirm', 'river stone login words 31'], ['lost-payment', 'cedar lamp pay words 47'], ['lost-payment-confirm', 'cedar lamp pay words 47']]) await browser.fill(stranger, id, value); };
    await fill('erin', erinWords);
    await browser.click(stranger, '#lost-submit');
    await until(stranger, `document.querySelector('#review-dialog').open === true`, 'the review of the recovery', 240000);
    const review = await browser.ask(stranger, `({ title: document.querySelector('#review-title').textContent, body: document.querySelector('#review-body').innerText })`);
    await shot(stranger, '61-recover-words-review', 1280);
    await browser.ask(stranger, `(document.querySelector('#review-dialog').close('cancel'), true)`);
    expect(review.title === 'Recover @erin on this browser' && review.body.includes('Your recovery words') && !review.body.includes('Recovery Kit'), JSON.stringify(review).slice(0, 300));
    await until(stranger, `!document.querySelector('#notice').className.includes('busy')`, 'the wallet is done');
    await fill('carol', words);
    await browser.click(stranger, '#lost-submit');
    await notice(stranger, 'This account also needs its Recovery Kit. Choose the file, or type the printed sheet.', 'the kit is asked for', 240000);
    return { review: review.body.replace(/\s+/g, ' ').slice(0, 200) };
  });
  // The step "recovery-kit" of campaign/lib/browser-check.mjs, with its selectors in its order: carol's Recovery Kit in a
  // browser that never saw her account, with her words, up to the review of a recovery, which is cancelled.
  await step('flow: the Recovery Kit in a fresh browser, with the words, up to the review of a recovery (cancelled)', async () => {
    const { words, kit } = await browser.ask(alice, `fetch('/__papers').then(r => r.json())`);
    const kitDir = path.join(downloads, 'kit'); await mkdir(kitDir, { recursive: true });
    const kitFile = path.join(kitDir, `time-recovery-kit-carol-${'c6'.repeat(4)}.json`); await writeFile(kitFile, kit);
    const stranger = await opened(null);
    expect((await browser.ask(stranger, `Object.keys(localStorage).filter((k) => k.includes('carol')).length`)) === 0, 'the fresh browser holds something of carol');
    await browser.ask(stranger, `(document.querySelector('#way-sheet').open = true, true)`);
    await browser.click(stranger, '#lost-open');
    await until(stranger, `document.querySelector('#lost-form').getClientRects().length > 0`, 'the recover panel opens');
    await browser.fill(stranger, 'lost-name', '');
    await browser.ask(stranger, `(document.querySelector('#lost-kit').open = true, true)`);
    const root = await cdp.send('DOM.getDocument', { depth: 0 }, stranger.sessionId), input = await cdp.send('DOM.querySelector', { nodeId: root.root.nodeId, selector: '#lost-file' }, stranger.sessionId);
    await cdp.send('DOM.setFileInputFiles', { files: [kitFile], nodeId: input.nodeId }, stranger.sessionId);
    const read = await until(stranger, `(() => { const s = document.querySelector('#lost-file-status'); return !s.hidden && s.textContent ? { says: s.textContent, name: document.querySelector('#lost-name').value } : null; })()`, 'the panel reads the kit');
    expect(read.says === 'This is the Recovery Kit of @carol.' && read.name === 'carol', JSON.stringify(read));
    await browser.fill(stranger, 'lost-phrase', words);
    for (const [id, value] of [['lost-login', 'river stone login words 31'], ['lost-login-confirm', 'river stone login words 31'], ['lost-payment', 'cedar lamp pay words 47'], ['lost-payment-confirm', 'cedar lamp pay words 47']]) await browser.fill(stranger, id, value);
    await browser.click(stranger, '#lost-submit');
    await until(stranger, `document.querySelector('#review-dialog').open === true`, 'the review of the recovery', 240000);
    const review = await browser.ask(stranger, `({ title: document.querySelector('#review-title').textContent, body: document.querySelector('#review-body').innerText })`);
    await shot(stranger, '60-recover-review', 1280);
    await browser.ask(stranger, `(document.querySelector('#review-dialog').close('cancel'), true)`);
    expect(review.title === 'Recover @carol on this browser' && review.body.includes('Your Recovery Kit and your recovery words'), JSON.stringify(review).slice(0, 300));
    await until(stranger, `!document.querySelector('#notice').className.includes('busy')`, 'the wallet is done');
    const after = await browser.ask(stranger, `({ stored: Object.keys(localStorage).filter((k) => k.includes('carol')).length, secrets: document.querySelector('#lost-phrase').value.length + document.querySelector('#lost-login').value.length + document.querySelector('#lost-payment').value.length })`);
    expect(after.stored === 0 && after.secrets === 0, JSON.stringify(after));
    // Other words do not open it.
    await browser.fill(stranger, 'lost-phrase', 'bababa bababa bababa bababa bababa');
    for (const [id, value] of [['lost-login', 'river stone login words 31'], ['lost-login-confirm', 'river stone login words 31'], ['lost-payment', 'cedar lamp pay words 47'], ['lost-payment-confirm', 'cedar lamp pay words 47']]) await browser.fill(stranger, id, value);
    await browser.click(stranger, '#lost-submit');
    await notice(stranger, 'These recovery words do not open this Recovery Kit, or the file is damaged.', 'the wrong words are refused', 240000);
    return { said: read.says, review: review.body.replace(/\s+/g, ' ').slice(0, 200) };
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
// A busy network (web-v4/wallet/busy.mjs; preview-server.mjs, /__busy): the start while every /api/ route answers 503
// for a while (the header and the quiet notice, then ready without a reload), an open account whose reads are refused
// (the header says busy, signing stays on), a payment and a freeze the network does not take (the wallet's words; the
// urgent notice and "Try again"), the test faucet that stays busy, and a file of the page answered 429.
if (only.has('busy')) for (const width of widths) {
  const busyFor = (page, query) => browser.ask(page, `fetch('/__busy?${query}').then(r => r.json())`);
  const read = (page) => browser.ask(page, `({ header: document.querySelector('#network-status').textContent, notice: document.querySelector('#notice').hidden ? '' : document.querySelector('#notice').innerText.replace(/\\s+/g, ' ').trim(), kind: document.querySelector('#notice').className, send: document.querySelector('#send-submit').disabled, verified: document.querySelector('#account-verification').textContent, wide: document.documentElement.scrollWidth > window.innerWidth, counted: document.documentElement.dataset.busyAnswers || '0' })`);
  const carol = async () => { const page = await opened('protected', width); await browser.ask(page, `fetch('/__reset').then(() => true)`); await unlock(page, 'carol'); return page; };
  const confirmReview = async (page) => { await until(page, `document.querySelector('#review-dialog').open`, 'the review'); await delay(800); await browser.click(page, '#review-confirm'); };
  await step(`busy ${width}: the start while the network is busy, then ready without a reload`, async () => {
    const page = await opened(null, width);
    try {
      await busyFor(page, 'status=503&seconds=9&retry=2');
      await browser.go(page, W + '/');
      await until(page, `document.querySelector('#network-status').textContent === 'Connecting… The network is busy. Trying again…' && !document.querySelector('#notice').hidden`, 'the busy line', 30000);
      const seen = await read(page);
      expect(seen.notice === 'The network is busy. The wallet keeps asking and is ready as soon as it answers. Nothing needs doing.' && seen.kind === 'notice busy' && !seen.wide, JSON.stringify(seen));
      await shot(page, '90-busy-start', width);
      await until(page, `!document.querySelector('#auth-submit').disabled`, 'ready without a reload', 90000);
      await shot(page, '91-busy-start-ready', width);
      return { ...seen, after: (await read(page)).header };
    } finally { await busyFor(page, 'status='); }
  });
  await step(`busy ${width}: an open account whose reads are refused: the header says busy, signing stays on`, async () => {
    const page = await carol();
    try {
      await busyFor(page, 'status=429&route=/api/view-proof&seconds=30&retry=3');
      await until(page, `document.querySelector('#network-status').textContent === 'The network is busy. Trying again…'`, 'the busy line', 30000);
      const seen = await read(page);
      expect(seen.send === false && !/Verification paused/.test(seen.notice) && seen.verified === 'Checked by this browser' && !seen.wide, JSON.stringify(seen));
      await shot(page, '92-busy-header', width);
      await busyFor(page, 'status=');
      await until(page, `/^Network checked/.test(document.querySelector('#network-status').textContent)`, 'the header back', 40000);
      return seen;
    } finally { await busyFor(page, 'status='); }
  });
  await step(`busy ${width}: a payment the network does not take: kept, said, then sent as it is from Activity`, async () => {
    const page = await carol();
    try {
      await browser.click(page, '.nav [data-panel="send"]'); await browser.fill(page, 'recipient', 'bob'); await browser.fill(page, 'amount', '0.01'); await browser.fill(page, 'send-payment', PAYMENT);
      await busyFor(page, 'status=503&route=/api/submit&count=10&retry=1');
      await browser.click(page, '#send-submit'); await confirmReview(page);
      await notice(page, 'The network is busy, so this signed action was not sent yet.', 'the words of an action kept', 90000);
      const seen = await read(page);
      expect(seen.send === false && !seen.wide, JSON.stringify(seen));
      await shot(page, '93-busy-payment-kept', width);
      await browser.click(page, '.nav [data-panel="activity"]');
      await until(page, `[...document.querySelectorAll('#pending-panel button')].some(b => b.textContent === 'Retry the exact signed action')`, 'the kept action in Activity', 30000);
      await shot(page, '94-busy-payment-retry', width);
      await browser.ask(page, `([...document.querySelectorAll('#pending-panel button')].find(b => b.textContent === 'Retry the exact signed action').click(), true)`);
      await notice(page, 'The exact pending action is finalized.', 'the kept action sent', 90000);
      return seen;
    } finally { await busyFor(page, 'status='); }
  });
  await step(`busy ${width}: a freeze the network does not take: the urgent notice, and "Try again" sends it`, async () => {
    const page = await carol();
    try {
      await browser.click(page, '#freeze-switch'); await until(page, `document.querySelector('#freeze-form').getClientRects().length > 0`, 'the step that freezes');
      await browser.ask(page, `(document.querySelector('#freeze-method').value = 'payment', document.querySelector('#freeze-method').dispatchEvent(new Event('change', { bubbles: true })), true)`);
      await browser.fill(page, 'freeze-secret', PAYMENT);
      await busyFor(page, 'status=429&route=/api/submit&count=10&retry=1');
      await browser.click(page, '#freeze-form button[type=submit]'); await confirmReview(page);
      await until(page, `Boolean(document.querySelector('#notice-try-again'))`, 'the urgent notice', 120000);
      // The page scrolls to it smoothly (styles.css, prefers-reduced-motion: no-preference): given a moment to arrive.
      await until(page, `(() => { const box = document.querySelector('#notice-try-again').getBoundingClientRect(); return box.top >= 0 && box.bottom <= window.innerHeight; })()`, 'the urgent notice scrolled into view', 5000).catch(() => {});
      const seen = await read(page), button = await browser.ask(page, `(() => { const b = document.querySelector('#notice-try-again'), box = b.getBoundingClientRect(); return { height: Math.round(box.height), in_view: box.top >= 0 && box.bottom <= window.innerHeight, focused: document.activeElement === b }; })()`);
      expect(seen.notice === 'The network is busy, and “Freeze account” could not be sent yet. It is signed and kept in this browser. Press “Try again” to send the same action now. Try again' && seen.kind === 'notice error' && button.height >= 44 && button.in_view && button.focused && !seen.wide, JSON.stringify({ seen, button }));
      await shot(page, '95-busy-freeze-urgent', width);
      await browser.click(page, '#notice-try-again');
      await notice(page, 'Freeze account: sent and verified.', 'the freeze sent', 90000);
      await shot(page, '96-busy-freeze-sent', width);
      return { ...seen, button };
    } finally { await busyFor(page, 'status='); await browser.ask(page, `fetch('/__reset').then(() => true)`); }
  });
  await step(`busy ${width}: the test faucet stays busy`, async () => {
    const page = await opened('single', width); await unlock(page, 'alice');
    try {
      await busyFor(page, 'status=503&route=faucet&seconds=60&retry=2');
      await browser.click(page, '#faucet-button');
      await notice(page, 'The test faucet is busy. Nothing was asked. Try again in a minute.', 'the faucet is busy', 60000);
      await shot(page, '97-busy-faucet', width);
      return await read(page);
    } finally { await busyFor(page, 'status='); }
  });
  await step(`busy ${width}: a file of the page answered 429`, async () => {
    const page = await opened(null, width);
    try {
      await busyFor(page, 'status=429&route=/app.js&seconds=30&retry=2');
      await browser.go(page, W + '/');
      await until(page, `document.querySelector('#boot-failed').getClientRects().length > 0`, 'the message when app.js does not load', 30000);
      const says = await browser.ask(page, `document.querySelector('#boot-failed').innerText.replace(/\\s+/g, ' ').trim()`);
      expect(says === 'The wallet could not load. Check your connection and reload this page. Nothing was changed. Reload', says);
      await shot(page, '98-busy-file', width);
      return { says };
    } finally { await busyFor(page, 'status='); }
  });
}
// The market of seconds against bitcoin (market-ui.mjs), on the mock network with the setting (/__market?on=1): the
// menu, the addresses, a purchase from the offer to the pay screen and a payment of a part, a sell order read back, the
// purchase someone prepared for carol, and the traders' view. Each screen is looked at for sideways scrolling.
if (only.has('market')) {
  const codec = await import('../../shared/bitcoin-address.mjs');
  const address = (byte) => codec.scriptToAddress('0014' + byte.repeat(20), 'testnet3');
  const market = (page, query) => browser.ask(page, `fetch('${query}').then(r => r.json())`);
  const view = (page) => browser.ask(page, `document.querySelector('#market-view').innerText.replace(/\\s+/g, ' ').trim()`);
  const wide = (page) => browser.ask(page, `document.documentElement.scrollWidth > window.innerWidth + 1`);
  const shown = (page, words, what = words) => until(page, `document.querySelector('#market-view').innerText.replace(/\\s+/g, ' ').toLowerCase().includes(${JSON.stringify(words.toLowerCase())})`, what, 60000);
  const toMarket = async (page) => { await browser.click(page, '.nav [data-panel="more"]'); await until(page, `!document.querySelector('#tab-market').hidden`, 'the Market row under More'); await browser.click(page, '#tab-market'); await shown(page, 'Buy and sell seconds for bitcoin'); };
  const confirm = async (page, title) => {
    await until(page, `document.querySelector('#review-dialog').open === true`, 'the review');
    const said = await browser.ask(page, `({ title: document.querySelector('#review-title').textContent, body: document.querySelector('#review-body').innerText, ack: document.querySelector('#review-ack-text').textContent })`);
    expect(said.title === title, `the review is titled "${said.title}", expected "${title}"`);
    return said;
  };
  const sign = async (page) => { await browser.ask(page, `(() => { const box = document.querySelector('#review-ack'); if (!document.querySelector('#review-ack-wrap').hidden && !box.checked) box.click(); return true; })()`); await delay(800); await browser.click(page, '#review-confirm'); };
  for (const width of widths) {
    // Addresses of this width's own: an address serves once, and the mock chain remembers the widths before.
    const mark = String(widths.indexOf(width) % 10), mine = [await address('7' + mark), await address('8' + mark), await address('9' + mark)];
    await step(`market ${width}: nowhere without the setting; menu, addresses, a purchase and its pay screen (alice, one key)`, async () => {
      const page = await opened('single', width);
      await market(page, '/__market?on=0'); await unlock(page, 'alice');
      await browser.click(page, '.nav [data-panel="more"]');
      expect(await browser.ask(page, `document.querySelector('#tab-market').hidden && document.querySelector('#home-market-row').hidden`), 'the market shows on a network without it');
      await market(page, '/__market?on=1'); await browser.click(page, '.nav [data-panel="home"]'); await browser.click(page, '#refresh');
      await until(page, `!document.querySelector('#home-market-row').hidden`, 'the Market line on Home');
      await shot(page, 'm01-home', width);
      await toMarket(page); await shot(page, 'm02-menu', width, { full: true });
      const note = await browser.text(page, '#market-test-note'); expect(/test bitcoin \(Bitcoin testnet\)/.test(note), note);
      // A. my Bitcoin addresses
      await browser.click(page, '#market-open-addresses'); await shown(page, 'Paste one address, or several');
      await browser.fill(page, 'market-address-input', mine.join('\n') + '\nbc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\nnot an address');
      await browser.click(page, '#market-address-add'); await shown(page, '3 addresses added. Nothing was published.');
      const listed = await browser.ask(page, `[...document.querySelectorAll('#market-address-list .market-address')].map(n => n.textContent.replace(/ /g, ''))`);
      expect(JSON.stringify(listed) === JSON.stringify(mine), 'the list shows ' + JSON.stringify(listed));
      expect(!(await wide(page)), 'the addresses make the page scroll sideways'); await shot(page, 'm03-addresses', width, { full: true });
      // B. buy
      await browser.click(page, '#market-back'); await browser.click(page, '#market-open-buy'); await shown(page, 'Find the best offer');
      await browser.fill(page, 'market-buy-amount', '60'); await browser.click(page, '#market-buy-find'); await shown(page, 'Review this purchase');
      const offer = await view(page); expect(/60 seconds for 0\.00015000 BTC \(15,000 satoshis\)/.test(offer) && /Price 250 satoshis for one second/.test(offer) && /Deposit 3 seconds, locked now/.test(offer), offer);
      expect(!(await wide(page)), 'the offer makes the page scroll sideways'); await shot(page, 'm04-offer', width, { full: true });
      await browser.click(page, '#market-buy-review'); const review = await confirm(page, 'Buy seconds with bitcoin'); await shot(page, 'm05-review-buy', width);
      expect(/You will pay\s+0\.00015000 BTC/.test(review.body) && /Total\s+3\.001 seconds leave your balance now/.test(review.body) && /I lose the deposit/.test(review.ack), review.body);
      await sign(page); await shown(page, 'Pay exactly', 'the pay screen');
      const pay = await browser.ask(page, `({ address: document.querySelector('#market-pay-address').textContent.replace(/ /g, ''), amount: document.querySelector('#market-pay-amount').firstChild.textContent, link: document.querySelector('#market-pay-link').href, state: document.querySelector('#market-pay-state').innerText.replace(/\\s+/g, ' ') })`);
      // The address on the screen is the one the mock chain holds for this fill, turned into an address here.
      const held = await market(page, '/v1/market/fills/' + (/Purchase number Fill ([0-9]+)/.exec(await view(page)) ?? [])[1]);
      expect(pay.address === await codec.scriptToAddress(held.fill.script, 'testnet3') && pay.amount === '0.00015000 BTC' && pay.link === 'bitcoin:' + pay.address + '?amount=0.00015000' && /Waiting for payment/.test(pay.state), JSON.stringify(pay));
      expect(!(await wide(page)), 'the pay screen scrolls sideways'); await shot(page, 'm06-pay', width, { full: true });
      // The prover's part: a payment of a part is proven. The screen reads the fill again and shows what is still to pay.
      const fill = (/Purchase number Fill ([0-9]+)/.exec(await view(page)) ?? [])[1]; expect(fill, 'the pay screen names its fill');
      await market(page, '/__market-pay?fill=' + fill + '&sats=5000'); await browser.click(page, '#market-pay-refresh'); await shown(page, 'Part counted');
      expect(await browser.ask(page, `document.querySelector('#market-pay-amount').firstChild.textContent`) === '0.00010000 BTC', 'what is still to pay was not read again');
      await shot(page, 'm07-pay-part', width, { full: true });
      await market(page, '/__market-pay?fill=' + fill + '&sats=10000'); await browser.click(page, '#market-pay-refresh'); await shown(page, 'This purchase has ended');
      await shot(page, 'm08-paid', width, { full: true });
      // B. sell, and the order read back
      await browser.click(page, '#market-back'); await browser.click(page, '#market-open-sell'); await shown(page, 'Seconds to sell');
      await browser.fill(page, 'market-sell-amount', '5'); await browser.fill(page, 'market-sell-price', '255'); await browser.click(page, '#market-sell-address-1');
      await browser.ask(page, `(document.querySelector('.market-terms').open = true)`); expect(!(await wide(page)), 'the sell form scrolls sideways'); await shot(page, 'm09-sell', width, { full: true });
      await browser.click(page, '#market-sell-review'); const selling = await confirm(page, 'Sell seconds for bitcoin'); await shot(page, 'm10-review-sell', width);
      expect(selling.body.replace(/ /g, '').includes(mine[0]) && selling.body.replace(/ /g, '').includes(mine[1]), 'the review shows both addresses whole: ' + selling.body);
      await sign(page); await shown(page, 'is on the chain', 'the order read back');
      const back = await browser.ask(page, `[...document.querySelectorAll('#market-made .market-address')].map(n => n.textContent.replace(/ /g, ''))`);
      expect(JSON.stringify(back) === JSON.stringify(mine.slice(0, 2)), 'read back: ' + JSON.stringify(back));
      expect(!(await wide(page)), 'my orders scroll sideways'); await shot(page, 'm11-mine', width, { full: true });
      return { offer: offer.slice(0, 120), pay, back };
    });
    await step(`market ${width}: a purchase someone prepared for a protected account, with the payment password field (carol)`, async () => {
      const page = await opened('protected', width);
      await market(page, '/__market?on=1'); await unlock(page, 'carol'); await toMarket(page);
      await shown(page, 'prepared for you'); await browser.click(page, '#market-open-mine'); await shown(page, 'Prepared for you by account 2');
      await shot(page, 'm12-mine-protected', width, { full: true });
      await browser.ask(page, `([...document.querySelectorAll('#market-purchases .row')].find(row => /Prepared for you/.test(row.innerText)).querySelector('button').click(), true)`); await shown(page, 'Someone else prepared this purchase for you');
      const text = await view(page); expect(/far above another offer on the list: 420 satoshis for one second, against /.test(text), text);
      expect(await browser.ask(page, `!document.querySelector('#market-payment-wrap').hidden && document.querySelector('#market-pay').contains(document.querySelector('#market-payment'))`), 'the payment password field is on the pay screen of a protected account');
      expect(!(await wide(page)), 'the pay screen scrolls sideways'); await shot(page, 'm13-pay-helper', width, { full: true });
      // The payment key signs for a protected account (security-ui.mjs, marketAction). Giving up this purchase would count its 40 seconds
      // against a daily limit of 30: refused in words, before any review. A purchase within the limit is reviewed and signed.
      await browser.fill(page, 'market-payment', PAYMENT); await browser.click(page, '#market-pay-release');
      await notice(page, 'Daily limit reached. Giving up counts 40.001 seconds against your daily limit', 'the daily limit refuses the release');
      await browser.click(page, '#market-back'); await browser.click(page, '#market-open-buy'); await shown(page, 'Find the best offer');
      await browser.fill(page, 'market-buy-amount', '20'); await browser.click(page, '#market-buy-find'); await shown(page, 'Review this purchase');
      await browser.fill(page, 'market-payment', PAYMENT); await browser.click(page, '#market-buy-review');
      const signed = await confirm(page, 'Buy seconds with bitcoin');
      expect(/Signed by\s+Your payment key, with your payment password/.test(signed.body) && /Daily limit\s+1\.001 seconds count against your daily limit/.test(signed.body), signed.body.slice(-400));
      await shot(page, 'm13b-review-protected', width); await sign(page); await notice(page, 'The deposit is locked.', 'the take signed by the payment key');
      expect(await browser.ask(page, `document.querySelector('#market-payment').value === ''`), 'the payment password stays in its field');
      return { text: text.slice(0, 160) };
    });
    await step(`market ${width}: the traders' view: the book, the chart, the forms and the service's flags (alice)`, async () => {
      const page = await opened('single', width);
      await market(page, '/__market?on=1'); await unlock(page, 'alice'); await toMarket(page);
      await browser.click(page, '#market-open-trade'); await shown(page, 'Order book');
      await until(page, `document.querySelectorAll('#market-chart-section svg rect').length >= 5`, 'the candles');
      const seen = await browser.ask(page, `({ asks: document.querySelectorAll('#market-asks tbody tr').length, bids: document.querySelectorAll('#market-bids tbody tr').length, candles: document.querySelectorAll('#market-chart-section svg rect').length, checked: /rows the chain keeps/.test(document.querySelector('#market-chart-section').innerText) })`);
      expect(seen.asks >= 3 && seen.bids >= 2 && seen.candles >= 5 && seen.checked, JSON.stringify(seen));
      expect(!(await wide(page)), 'the traders view scrolls sideways'); await shot(page, 'm14-trade', width, { full: true });
      await market(page, '/__market-index?consistent=0&tape=0&lag=40'); await browser.click(page, '#market-back'); await browser.click(page, '#market-open-trade'); await shown(page, 'does not agree with the chain');
      await shot(page, 'm15-trade-flags', width, { full: true }); await market(page, '/__market-index');
      // A stop order: kept in this browser, then fired by the book as the wallet reads it, and nothing is signed.
      await browser.click(page, '#market-back'); await browser.click(page, '#market-open-trade'); await shown(page, 'A new stop order');
      await browser.ask(page, `(document.querySelector('#market-stop-side').value = 'buy', document.querySelector('#market-stop-when').value = 'at_or_above', true)`);
      await browser.fill(page, 'market-stop-amount', '20'); await browser.fill(page, 'market-stop-trigger', '240'); await browser.fill(page, 'market-stop-size', '10'); await browser.fill(page, 'market-stop-limit', '251');
      await browser.click(page, '#market-stop-keep'); await notice(page, 'The stop order is kept in this browser. Nothing was signed', 'the stop order is kept');
      await until(page, `/Fired/.test(document.querySelector('#market-stop-list').innerText)`, 'the stop order fires on the book', 90000);
      expect(!(await wide(page)), 'the stop orders scroll sideways'); await shot(page, 'm16-stops', width, { full: true });
      await browser.ask(page, `(document.querySelector('#market-stop-list button.secondary').click(), true)`);
      return seen;
    });
  }
}
for (const page of pages) for (const p of page.problems) if (!/favicon\.ico/.test(p.text)) log.push(`page: ${p.kind}: ${p.text}`);
await writeFile(path.join(out, 'log.txt'), log.join('\n') + '\n');
console.log(`${out}\n${log.join('\n')}`);
await chrome.close();
