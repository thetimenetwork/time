// The explorer in a browser: reads the page's one setting, loads what the checks need (and the optional
// join.json) from fixed places next to the page, and starts the views. Everything else is in the modules, which take
// their parts as arguments and are tested without a browser.
import { createStrings } from './strings.mjs';
import { createApi, createLive, apiOrigin } from './client.mjs';
import { createChecker } from './check.mjs';
import { createExplorer } from './views.mjs';

const t = createStrings(document.documentElement.lang || 'en');
// The API origin: the content of <meta name="time-api-origin">. Empty means this page's origin.
let origin;
try { origin = apiOrigin(document.querySelector('meta[name="time-api-origin"]')?.getAttribute('content') ?? ''); } catch {
  // A setting that is not a plain origin is not guessed at: the page says so and stops.
  document.getElementById('view').textContent = t('error.config');
  throw new Error('The API origin of this page is not a plain origin');
}
const api = createApi({ origin });

// The trust manifest, the SDK, the light client and the verifier come from this page's own
// origin, at fixed addresses next to it: never from the API origin, and never from an address a
// value from the network could choose.
const checker = createChecker({
  api,
  sdk: globalThis.TimeSDK,
  loadTrust: async () => {
    const response = await fetch(new URL('trust-manifest.json', document.baseURI), { cache: 'no-store', credentials: 'omit', redirect: 'error' });
    // No manifest was installed with the page: that is remembered. Any other failure (the host
    // limits requests, the connection dropped) is thrown, and the manifest is asked for again later.
    if (response.status === 404) return null;
    if (!response.ok) throw new Error('The trust manifest could not be loaded now');
    return response.json();
  },
  loadVerifier: () => import('./sdk/proof-verifier.mjs'),
  createLightClient: async (options) => (await import('./sdk/light-client.mjs')).createLightClient(options),
});

// This network's facts for "Run a validator" (join.json): optional, and from this page's own origin like the
// trust manifest. None installed (404) is null. Otherwise the text of the file goes to the view, which reads it
// as it reads anything from outside (format.mjs, readJoin). Any other failure is thrown: the view then shows its
// general explanation, and asks again at the next view.
const loadJoin = async () => {
  const response = await fetch(new URL('join.json', document.baseURI), { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15000) });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error('The page\'s join.json could not be loaded now');
  return response.text();
};

const live = typeof EventSource === 'function' ? createLive({ api, open: (url) => new EventSource(url), timers: window }) : null;
createExplorer({ document, window, api, checker, live, t, timers: window, loadJoin }).start();
