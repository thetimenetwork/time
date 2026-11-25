// The page that never starts. When a script or the stylesheet of the wallet does not load, or the page has not started
// 20 seconds after its document was read, the wallet says so in plain words with a button that reloads it (index.html:
// #boot-failed). Before, such a page showed its form and never answered (seen in a real browser on 23 November 2026).
//
// It cannot live in app.js: the page it watches for is one where app.js, or a module app.js imports, did not load. So it
// is this small classic script, the first one of the page, read before the stylesheet and every module. The page's start
// (app.js, start) sends the event `time-wallet:started` on the document, and this script stands down for good. It holds
// no secret, sends nothing anywhere and changes nothing but the message: the page's policy allows no inline script, so
// it is a file of its own.
(() => {
  const WAIT_MS = 20000;
  let started = false, failed = false, timer = null;
  function show() {
    if (started || failed) return;
    failed = true;
    const say = () => {
      const box = document.getElementById('boot-failed');
      if (!box) return;
      document.body.classList.add('boot-failed');
      box.hidden = false;
      document.getElementById('boot-reload')?.addEventListener('click', () => location.reload());
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', say, { once: true }); else say();
  }
  // A script or a stylesheet that does not load fires `error` on its own element, which does not bubble: it is caught
  // on its way down, at the window.
  window.addEventListener('error', event => {
    const element = event.target;
    if (!element || typeof element.tagName !== 'string') return;
    if (element.tagName === 'SCRIPT' || (element.tagName === 'LINK' && /(^|\s)stylesheet(\s|$)/i.test(element.rel || ''))) show();
  }, true);
  document.addEventListener('DOMContentLoaded', () => { if (!started) timer = setTimeout(show, WAIT_MS); }, { once: true });
  document.addEventListener('time-wallet:started', () => { started = true; if (timer !== null) clearTimeout(timer); }, { once: true });
})();
