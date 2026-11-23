// The network menu of the Time pages: a small button that says which network a page belongs to, and opens the
// list of networks, each leading to the same page on that network. One file serves every page (the main page,
// the wallet, the explorer, the faucet, the demo blog). A page mounts it where it has an element for it:
//
//   <span data-network-menu data-app="wallet"></span>
//   <script type="module" src="/web-v4/shared/network-menu.js"></script>
//
// The public names follow one scheme under the project's domain (testnet/plan.mjs, domainNames, builds the same):
//
//   <network>.thetimenetwork.org          the main page of a network; the domain's own name and www show the
//                                         main page of APEX_NETWORK
//   <app>.<network>.thetimenetwork.org    wallet, explorer, api, faucet, blog
//
// A page under any other name (a laboratory, a trial, the content network's own address) says so, and its list
// still leads to the public networks. Nothing is fetched to draw the menu and nothing is stored. The one request
// it makes is the wallet's own /api/network, on a wallet opened under a name outside the scheme: when that
// wallet's gateway says its address is another one, the page says where the wallet is now (see movedNotice).

export const DOMAIN = 'thetimenetwork.org';
export const APEX_NETWORK = 'testnet';
/// The public networks, in the order the menu lists them. A network that is not launched is shown, and leads nowhere.
export const NETWORKS = Object.freeze([
  Object.freeze({ id: 'mainnet', name: 'Mainnet', note: 'Not launched yet', launched: false }),
  Object.freeze({ id: 'testnet', name: 'Testnet', note: 'Test seconds with no value', launched: true }),
]);
/// The pages that carry the menu. `api` has a name of its own but no page.
export const APPS = Object.freeze(['site', 'wallet', 'explorer', 'faucet', 'blog']);
const NAMED = Object.freeze([...APPS.filter((app) => app !== 'site'), 'api']);
const LABEL = /^[a-z][a-z0-9-]{0,30}$/;

/// The host name of a page of a network: `hostFor('wallet', 'testnet')` is wallet.testnet.thetimenetwork.org.
export function hostFor(app, network, domain = DOMAIN) {
  if (app !== 'site' && !NAMED.includes(app)) throw new Error(`unknown page ${app}`);
  if (!LABEL.test(String(network)) || network === 'www') throw new Error(`not a network name: ${network}`);
  return app === 'site' ? `${network}.${domain}` : `${app}.${network}.${domain}`;
}

/// The network a host name belongs to, or null for a name outside the scheme.
export function networkOf(hostname, domain = DOMAIN) {
  const host = String(hostname ?? '').toLowerCase().replace(/\.$/, '');
  if (host === domain || host === `www.${domain}`) return APEX_NETWORK;
  if (!host.endsWith(`.${domain}`)) return null;
  const parts = host.slice(0, -(domain.length + 1)).split('.');
  const id = parts.length === 1 ? parts[0] : parts.length === 2 && NAMED.includes(parts[0]) ? parts[1] : null;
  return id !== null && LABEL.test(id) && id !== 'www' ? id : null;
}

/// What the menu shows for a page: the label of its network, and one entry per network.
export function menuModel({ app, hostname }) {
  const page = APPS.includes(app) ? app : 'site';
  const current = networkOf(hostname);
  const known = NETWORKS.find((network) => network.id === current);
  const label = known ? known.name : current ? current[0].toUpperCase() + current.slice(1) : 'Other network';
  const items = NETWORKS.map((network) => ({ id: network.id, name: network.name, note: network.note, current: network.id === current, href: network.launched ? `https://${hostFor(page, network.id)}/` : null }));
  // A network under the domain that the list does not know (a trial): shown as the current one, after the others.
  if (current !== null && !known) items.push({ id: current, name: label, note: 'Not a public network', current: true, href: null });
  return { current, known: Boolean(known), label, items };
}

/// Where a wallet that was opened under a name outside the scheme now lives, from its gateway's /api/network, or
/// null: only an HTTPS address under the domain, other than this page's own, counts.
export function movedTo({ config, origin }) {
  const target = config && typeof config.walletOrigin === 'string' ? config.walletOrigin : null;
  if (!target) return null;
  let url;
  try { url = new URL(target); } catch { return null; }
  if (url.protocol !== 'https:' || url.origin !== target || url.origin === origin || networkOf(url.hostname) === null) return null;
  return url.origin;
}

// ---- in a page

const node = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = text; return element; };

function draw(host) {
  const model = menuModel({ app: host.dataset.app, hostname: location.hostname });
  const details = node('details', 'tn-menu');
  const summary = node('summary', 'tn-button');
  summary.setAttribute('aria-label', `Network: ${model.label}. Show the networks`);
  summary.append(node('span', `tn-dot tn-${model.known ? model.current : 'other'}`), node('span', 'tn-label', model.label), node('span', 'tn-caret'));
  const list = node('ul', 'tn-list');
  for (const item of model.items) {
    const entry = node('li');
    const inner = item.href && !item.current ? node('a', 'tn-item') : node('span', 'tn-item');
    if (inner.tagName === 'A') inner.href = item.href;
    if (item.current) { inner.classList.add('tn-current'); inner.setAttribute('aria-current', 'page'); }
    if (!item.href && !item.current) { inner.classList.add('tn-off'); inner.setAttribute('aria-disabled', 'true'); }
    const words = node('span', 'tn-words');
    words.append(node('span', 'tn-name', item.name), node('span', 'tn-note', item.current ? `${item.note} · you are here` : item.note));
    inner.append(node('span', `tn-dot tn-${NETWORKS.some((network) => network.id === item.id) ? item.id : 'other'}`), words);
    entry.append(inner);
    list.append(entry);
  }
  if (!model.current) list.append(node('li', 'tn-foot', 'This page is not one of the public networks.'));
  details.append(summary, list);
  host.replaceChildren(details);
  document.addEventListener('click', (event) => { if (details.open && !details.contains(event.target)) details.open = false; });
  details.addEventListener('keydown', (event) => { if (event.key === 'Escape' && details.open) { details.open = false; summary.focus(); } });
}

async function movedNotice(app) {
  if (app !== 'wallet' || networkOf(location.hostname) !== null) return;
  const config = await fetch('/api/network', { cache: 'no-store', credentials: 'same-origin' }).then((answer) => (answer.ok ? answer.json() : null)).catch(() => null);
  const target = movedTo({ config, origin: location.origin });
  if (!target) return;
  const box = node('div', 'tn-moved');
  box.setAttribute('role', 'alert');
  const link = node('a', null, new URL(target).host);
  link.href = `${target}/`;
  const first = node('p');
  first.append(node('strong', null, 'This wallet has a new address: '), link, node('strong', null, '.'));
  box.append(first, node('p', null, 'This old address still works for now. An account you made here is kept in this browser under this address only. To take it to the new address: open it here, go to Keys and download your backup file, then open the new address and choose "Restore from a backup file".'));
  document.body.prepend(box);
}

if (typeof document !== 'undefined' && typeof location !== 'undefined') {
  const hosts = [...document.querySelectorAll('[data-network-menu]')];
  if (hosts.length) {
    const style = document.createElement('link');
    style.rel = 'stylesheet';
    style.href = new URL('./network-menu.css', import.meta.url).href;
    document.head.append(style);
    for (const host of hosts) draw(host);
    movedNotice(hosts[0].dataset.app).catch(() => {});
  }
}
