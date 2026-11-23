// The explorer's pages: home, block, action, account, validators. One page with addressable
// views (route.mjs). Everything it shows comes from the API (client.mjs) and is treated as
// written by an attacker: values pass a test of format.mjs before use, elements are made by
// dom.mjs only, and what the page has checked itself (check.mjs) is told apart from the index.
import { createDom } from './dom.mjs';
import { ApiFailure } from './client.mjs';
import { CheckFailure } from './check.mjs';
import { describeAction, differences } from './describe.mjs';
import { parseRoute, parseSearch, routeOfSearch, hrefOf, newPager, pagerLoaded, pagerCursor, pagerNext, pagerPrevious, canNext, canPrevious } from './route.mjs';
import { isHash, isHeight, isAccountId, isMicros, isName, isKey, isCount, isReference, cleanText, formatAmount, formatMicros, formatNumber, formatShare, formatTime, timeOfMicros, timeOfIso, ago, shortHex, hexOfBase64 } from './format.mjs';

const PAGE = 25, HOME_ROWS = 10, HOME_SCAN = 50;
/// The fixed parts of index.html and the entry of the strings table each one shows.
export const STATIC_TEXT = Object.freeze({
  'skip-link': 'page.skip', 'brand': 'page.brand', 'network-warning': 'page.warning', 'nav-home': 'page.home', 'nav-validators': 'page.validators', 'search-label': 'page.searchLabel', 'search-button': 'page.searchButton',
  'toggle-exact': 'page.exact', 'toggle-utc': 'page.utc', 'legend-title': 'page.legend', 'legend-index': 'page.legendIndex', 'legend-checked': 'page.legendChecked', 'legend-quoted': 'page.legendQuoted', 'trust-title': 'trust.title',
});

export function createExplorer({ document, window, api, checker, live = null, t, now = Date.now, timers = globalThis, locale, timeZone }) {
  const { h, quoted, sentence } = createDom(document);
  const $ = (id) => document.getElementById(id);
  const words = { h: t('unit.h'), min: t('unit.min'), s: t('unit.s'), micros: t('unit.micros'), thousands: t('unit.thousands'), decimal: t('unit.decimal') };
  const prefs = { exact: false, utc: false };
  let generation = 0, pending = [], refreshers = [], cleanups = [], trustInfo = null, lastStatus = null, tick = null, shown = false;
  const track = (promise) => { pending.push(promise.catch(() => {})); return promise; };

  // ------------------------------------------------------------------ values, each shown in one fixed way
  const missing = () => h('span', { class: 'missing', text: t('value.unreadable') });
  /// An element whose text depends on a preference or on the clock: `text()` is asked again
  /// whenever either changes.
  function living(className, text) {
    const element = h('span', { class: className, text: text() });
    refreshers.push(() => { element.textContent = text(); });
    return element;
  }
  const amountNode = (micros) => (isMicros(micros) ? living('amount', () => (prefs.exact ? formatMicros(micros, words) : formatAmount(micros, words))) : missing());
  const timeNode = (ms) => (ms === null ? missing() : living('time', () => formatTime(ms, { utc: prefs.utc, locale, timeZone }) ?? t('value.unreadable')));
  const agoText = (ms) => { const past = ago(ms, now()); return past ? t(`ago.${past.unit}`, { count: past.count }) : t('value.unreadable'); };
  const agoNode = (ms) => (ms === null ? missing() : living('ago', () => agoText(ms)));
  const numberNode = (value) => { const text = formatNumber(value, words); return text === null ? missing() : h('span', { class: 'number', text }); };
  const hexNode = (value) => (typeof value === 'string' && /^[0-9A-Fa-f]{1,128}$/.test(value) ? h('code', { class: 'hex', text: value }) : missing());
  const link = (route, text) => { const href = hrefOf(route); return href === null ? missing() : h('a', { href, text }); };
  const accountLink = (id) => (isAccountId(id) ? link({ view: 'account', id }, t('account.number', { id })) : missing());
  const blockLink = (height) => (isHeight(height) ? link({ view: 'block', height }, t('block.number', { height: formatNumber(height, words) })) : missing());
  const actionLink = (hash, text) => (isHash(hash) ? link({ view: 'action', hash }, text ?? t('action.link', { short: shortHex(hash) })) : missing());
  const nameNode = (name) => (isName(name) ? quoted(`@${name}`, t('quoted.name')) : missing());
  /// A value of an action's description (describe.mjs), by its type.
  function valueNode(value) {
    switch (value?.type) {
      case 'account': return accountLink(value.id);
      case 'nobody': return h('span', { text: t('account.nobody') });
      case 'amount': return amountNode(value.micros);
      case 'reference': return isReference(value.hex) ? quoted(value.hex, t('quoted.reference')) : missing();
      case 'key': return isKey(value.hex) ? hexNode(value.hex) : missing();
      case 'number': return numberNode(value.value);
      case 'name': return nameNode(value.name);
      case 'percent': return h('span', { text: t('percent', { value: value.value }) });
      case 'role': return h('span', { text: t(`role.${value.role}`) });
      case 'yesno': return h('span', { text: t(value.value ? 'value.yes' : 'value.no') });
      case 'action': return actionLink(value.hash);
      default: return missing();
    }
  }
  const fill = (key, parts) => sentence(t(key), parts);
  const describe = (action) => { const said = describeAction(action); return { said, nodes: fill(said.sentence, Object.fromEntries(Object.entries(said.params).map(([name, value]) => [name, valueNode(value)]))) }; };
  const source = (key, values) => h('small', { class: 'source', text: t(key, values) });
  const indexSource = (answer) => (isHeight(answer?.index?.indexed_height) ? source('source.indexAt', { height: formatNumber(answer.index.indexed_height, words) }) : source('source.index'));
  const facts = (rows) => h('dl', { class: 'facts' }, rows.filter(Boolean).map(([label, value]) => [h('dt', { text: t(label) }), h('dd', {}, value)]));
  const state = (className, key, values) => h('p', { class: `state ${className}`, text: t(key, values) });

  // ------------------------------------------------------------------ loading, failing, retrying
  /// What to show for a request that failed. For a failure that can pass (no connection, a rate
  /// limit, a busy service) the part is loaded again by itself after the wait, a few times.
  function failureBox(error, { notFound = 'error.notFound', notFoundValues, retry, auto }) {
    const failure = error instanceof CheckFailure && error.detail instanceof ApiFailure ? error.detail : error;
    let key = 'error.page', values, passing = false;
    if (failure instanceof ApiFailure) {
      if (failure.kind === 'network') { key = 'error.network'; passing = true; }
      else if (failure.kind === 'invalid') key = 'error.invalidAnswer';
      else if (failure.status === 404) { key = notFound; values = notFoundValues; }
      else if (failure.status === 429) { key = 'error.limited'; passing = true; }
      else if (failure.status === 503 || failure.status === 502) { key = 'error.unavailable'; passing = true; }
      else if (failure.status === 403) key = 'error.origin';
      else if (failure.status === 400 || failure.status === 414) key = 'error.badRequest';
      else { key = 'error.other'; values = { status: Number.isInteger(failure.status) ? failure.status : 0 }; }
    }
    const box = h('div', { class: key === notFound ? 'state empty' : 'state failed', attrs: { role: key === notFound ? 'status' : 'alert' } }, h('p', { text: t(key, values) }));
    if (failure instanceof ApiFailure && failure.kind === 'http' && failure.status !== 404 && (failure.code || failure.serverMessage)) {
      box.append(h('details', {}, h('summary', { text: t('error.serviceSaid') }), failure.code ? h('p', {}, quoted(failure.code, t('quoted.service'), 40)) : null, failure.serverMessage ? h('p', {}, quoted(failure.serverMessage, t('quoted.service'), 300)) : null));
    }
    if (retry && key !== notFound) {
      const seconds = Math.min(60, Math.max(2, failure instanceof ApiFailure && failure.retryAfter ? failure.retryAfter : 5));
      if (passing && auto) {
        const token = generation, timer = timers.setTimeout(() => { if (token === generation) retry(); }, seconds * 1000);
        cleanups.push(() => timers.clearTimeout(timer));
        box.append(h('p', { class: 'retrying', text: t('state.retrying', { seconds }) }));
      }
      box.append(h('button', { class: 'quiet', attrs: { type: 'button' }, on: { click: () => retry() }, text: t('state.retry') }));
    }
    return box;
  }
  /// A part of a view that loads by itself: its heading stays, its body shows "loading", then
  /// what `load` returns, or the failure with a way to try again. Other parts are not affected.
  function part(heading, load, options = {}) {
    const body = h('div', { class: 'part-body' });
    const title = heading ? h(options.level ?? 'h2', { attrs: { tabindex: '-1' }, text: heading }) : null;
    let attempts = 0;
    const run = () => {
      const token = generation;
      body.replaceChildren(h('p', { class: 'state loading', attrs: { role: 'status' }, text: t('state.loading') }));
      return track((async () => {
        try {
          const nodes = await load({ reload: run, title });
          if (token === generation) body.replaceChildren(...[nodes].flat(3).filter(Boolean));
        } catch (error) {
          if (token === generation) body.replaceChildren(failureBox(error, { ...options, retry: run, auto: attempts++ < 4 }));
        }
      })());
    };
    run();
    return h('section', { class: 'part' }, title, body);
  }
  /// A list read page by page. `fetchPage(cursor)` asks the API; `row(item)` makes one line.
  function pagedList(heading, fetchPage, row, emptyKey) {
    let pager = newPager();
    return part(heading, async ({ reload, title }) => {
      const answer = await fetchPage(pagerCursor(pager));
      pager = pagerLoaded(pager, answer);
      const items = Array.isArray(answer.items) ? answer.items.slice(0, 200) : [];
      const turn = (next) => () => { pager = next(pager); reload(); title?.focus?.(); };
      const pages = canNext(pager) || canPrevious(pager) ? h('nav', { class: 'pager', attrs: { 'aria-label': t('pager.label') } },
        h('button', { class: 'quiet', attrs: { type: 'button', ...(canPrevious(pager) ? {} : { 'aria-disabled': 'true' }) }, on: { click: canPrevious(pager) ? turn(pagerPrevious) : () => {} }, text: t('pager.previous') }),
        h('span', { text: t('pager.page', { page: pager.page + 1 }) }),
        h('button', { class: 'quiet', attrs: { type: 'button', ...(canNext(pager) ? {} : { 'aria-disabled': 'true' }) }, on: { click: canNext(pager) ? turn(pagerNext) : () => {} }, text: t('pager.next') })) : null;
      return [items.length ? h('ul', { class: 'rows' }, items.map(row)) : state('empty', emptyKey), pages, indexSource(answer)];
    });
  }
  /// One action in a list: what it did, when, and the way to its own page.
  function actionRow(item, { showBlock = true } = {}) {
    const { said, nodes } = describe(item), made = timeOfIso(item?.time);
    return h('li', { class: `row kind-${said.category}` }, h('p', { class: 'sentence' }, nodes),
      said.status ? h('p', { class: 'status', text: t(said.status) }) : null,
      item?.role === 'pending' ? h('p', { class: 'status', text: t('account.role.pending') }) : null,
      h('p', { class: 'meta' }, made === null ? null : [agoNode(made), ' · '], showBlock && isHeight(item?.height) ? [blockLink(item.height), ' · '] : null, actionLink(item?.hash, t('action.details'))));
  }
  const countText = (count) => (count === 0 ? t('actions.count.none') : count === 1 ? t('actions.count.one') : t('actions.count.many', { count: formatNumber(count, words) }));

  // ------------------------------------------------------------------ what was checked
  /// Why a check gave no result, in the page's words, with the technical text set apart.
  function checkFailureBox(failure) {
    const reason = ['refused', 'no_trust', 'wrong_network', 'no_verifier', 'trust_expired', 'unavailable', 'too_new'].includes(failure?.reason) ? failure.reason : 'unavailable';
    const box = h('div', { class: reason === 'refused' ? 'check bad' : 'check unknown', attrs: { role: reason === 'refused' ? 'alert' : 'status' } }, h('p', { class: 'verdict', text: t(`check.${reason}`) }));
    const detail = failure?.detail instanceof ApiFailure ? failure.detail.code ?? (failure.detail.status ? String(failure.detail.status) : failure.detail.kind) : typeof failure?.detail === 'string' ? failure.detail : null;
    if (detail) box.append(h('details', {}, h('summary', { text: t('check.detail') }), quoted(detail, t('quoted.service'), 300)));
    return box;
  }
  /// The note under figures of a proven state: checked here (and what that means), or why not.
  function stateNote(checked, failure) {
    if (checked) return h('div', { class: 'check ok' }, source('source.checked', { height: formatNumber(checked.height, words) ?? '?' }),
      h('details', {}, h('summary', { text: t('check.stateWhat') }), h('p', { text: t('check.stateText', { anchor: formatNumber(checked.anchorHeight ?? checked.height, words) ?? '?' }) })));
    return h('div', { class: 'check unknown' }, source('source.service'), h('details', {}, h('summary', { text: t('account.unchecked') }), checkFailureBox(failure)));
  }
  /// Reads a state through the check. Returns { checked, body, failure }:
  /// - checked: the proven state (show it as checked);
  /// - otherwise `body` is the service's answer, to be shown as its word, and `failure` says why
  ///   the page could not check it. A proof that does NOT verify shows nothing: it throws.
  async function readState(fetchBody, query) {
    try { const checked = await checker.checkState(fetchBody, query); return { checked, body: checked.body, failure: null }; } catch (error) {
      if (!(error instanceof CheckFailure)) throw error;
      if (error.reason === 'refused') throw error;
      if (error.reason === 'unavailable') throw error.detail;
      return { checked: null, body: await fetchBody(), failure: error };
    }
  }
  const refusedOr = (error, render) => { if (error instanceof CheckFailure && error.reason === 'refused') return [h('div', { class: 'check bad', attrs: { role: 'alert' } }, h('p', { class: 'verdict', text: t('check.stateRefused') }), checkFailureBox(error))]; return render(error); };

  // ------------------------------------------------------------------ home
  const cleanBlock = (item) => (item && isHeight(item.height) && isMicros(item.time_micros) && isCount(item.tx_count) ? { height: item.height, made: timeOfMicros(item.time_micros), micros: item.time_micros, count: item.tx_count, payments: isCount(item.payment_count) ? item.payment_count : 0 } : null);
  function viewHome() {
    let blocks = [], payments = [], status = lastStatus;
    const blockList = h('ul', { class: 'rows' }), paymentList = h('ul', { class: 'rows' }), networkBody = h('div', {}), liveLine = h('p', { class: 'live', attrs: { role: 'status' } });
    const blockRow = (block) => h('li', { class: 'row' }, h('p', { class: 'sentence' }, fill('home.blockRow', { link: blockLink(block.height), actions: countText(block.count), ago: block.made === null ? missing() : agoNode(block.made) })));
    const drawBlocks = () => blockList.replaceChildren(...(blocks.length ? blocks.map(blockRow) : [h('li', { class: 'state empty', text: t('home.noBlocks') })]));
    const drawPayments = () => paymentList.replaceChildren(...(payments.length ? payments.map((payment) => actionRow(payment)) : [h('li', { class: 'state empty', text: t('home.noPayments', { count: HOME_SCAN }) })]));
    const drawNetwork = () => {
      const network = status?.network ?? {}, newest = blocks[0] ?? null;
      const genesis = trustInfo?.genesisTimeMicros ?? null;
      const issued = newest && genesis !== null && BigInt(newest.micros) >= BigInt(genesis) ? (BigInt(newest.micros) - BigInt(genesis)).toString() : null;
      networkBody.replaceChildren(facts([
        ['home.chain', typeof network.chain_id === 'string' ? quoted(network.chain_id, t('quoted.chain'), 60) : missing()],
        ['home.networkId', hexNode(network.network_id)],
        ['home.height', newest ? [numberNode(newest.height), ' ', source('source.index')] : h('span', { text: t('home.noBlocks') })],
        newest ? ['home.blockTime', [timeNode(newest.made), ' (', agoNode(newest.made), ') ', source('source.index')]] : null,
        ['home.fee', isMicros(network.fee_micros) ? [amountNode(network.fee_micros), ' ', source('source.service')] : h('span', { text: t('home.feeUnknown') })],
        ['home.issued', issued !== null ? [amountNode(issued), ' ', h('small', { class: 'source', text: t('home.issuedHow') })] : h('span', { text: t(genesis === null ? 'home.issuedUnknown' : 'home.noBlocks') })],
      ]));
    };
    const addBlock = (item) => { const block = cleanBlock(item); if (!block || blocks.some((known) => known.height === block.height)) return; blocks = [block, ...blocks].sort((a, b) => (BigInt(b.height) > BigInt(a.height) ? 1 : -1)).slice(0, HOME_ROWS); drawBlocks(); drawNetwork(); };
    const addPayment = (item) => { if (!item || !isHash(item.hash) || !isHeight(item.height) || payments.some((known) => known.hash === item.hash)) return; payments = [item, ...payments].slice(0, HOME_ROWS); drawPayments(); };
    async function loadLists() {
      const answer = await api.blocks({ limit: HOME_SCAN });
      const listed = (Array.isArray(answer.items) ? answer.items : []).map(cleanBlock).filter(Boolean);
      blocks = listed.slice(0, HOME_ROWS);
      // The newest payments: read from the newest blocks that hold any, a few requests at most.
      const found = [];
      for (const block of listed.filter((item) => item.payments > 0).slice(0, 5)) {
        if (found.length >= HOME_ROWS) break;
        const actions = await api.blockActions(block.height, { limit: 50 });
        found.push(...(Array.isArray(actions.items) ? actions.items : []).filter((item) => item?.transfers === true && isHash(item.hash)).reverse());
      }
      payments = found.slice(0, HOME_ROWS);
      drawBlocks(); drawPayments(); drawNetwork();
    }
    const setLive = (name) => { liveLine.textContent = t(`live.${['live', 'connecting', 'waiting'].includes(name) ? name : 'idle'}`); };
    if (live) {
      const token = generation;
      live.listen({
        onState: (name) => { if (token === generation) setLive(name); },
        onEvent: ({ type, data }) => {
          if (token !== generation) return;
          if (type === 'block') addBlock(data); else if (type === 'payment') addPayment(data);
          else if (type === 'gap') { track(loadLists().catch(() => {})); liveLine.textContent = t('live.gap'); }
        },
      });
      live.start();
      // While the stream is down the lists are read again from time to time.
      const poll = timers.setInterval(() => { if (token === generation && live.state() !== 'live') track(loadLists().catch(() => {})); }, 10000);
      cleanups.push(() => { timers.clearInterval(poll); live.stop(); });
      setLive(live.state());
    } else setLive('idle');
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('home.title') }),
      part(t('home.network'), async () => { status = await loadStatus(); drawNetwork(); return networkBody; }),
      part(t('home.blocks'), async () => { await loadLists(); return [blockList, liveLine, source('source.index')]; }),
      h('section', { class: 'part' }, h('h2', { text: t('home.payments') }), paymentList, h('small', { class: 'source', text: `${t('home.paymentsNote', { count: HOME_SCAN })} ${t('source.index')}` }))];
  }

  // ------------------------------------------------------------------ block
  function viewBlock({ height }) {
    const shown = formatNumber(height, words);
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('block.title', { height: shown }) }),
      part(null, async () => {
        const answer = await api.block(height), block = answer.block ?? {};
        const made = timeOfMicros(block.time_micros), previous = (BigInt(height) - 1n).toString(), next = (BigInt(height) + 1n).toString();
        const more = isHeight(answer.index?.indexed_height) && BigInt(answer.index.indexed_height) > BigInt(height);
        return [facts([
          ['block.height', numberNode(height)],
          ['block.time', [timeNode(made), ' (', agoNode(made), ')']],
          ['block.hash', hexNode(isHash(block.hash) ? block.hash : null)],
          ['block.count', isCount(block.tx_count) ? h('span', { text: countText(block.tx_count) }) : missing()],
          ['block.payments', numberNode(block.payment_count)],
          ['block.proposer', hexNode(typeof block.proposer === 'string' && /^[0-9A-Fa-f]{40}$/.test(block.proposer) ? block.proposer : null)],
          ['block.results', h('span', { text: t(block.results_checked === true ? 'block.resultsYes' : 'block.resultsNo') })],
          isHeight(previous) ? ['block.previous', blockLink(previous)] : null,
          more ? ['block.next', blockLink(next)] : null,
        ]), indexSource(answer),
        pagedList(t('block.actions'), (cursor) => api.blockActions(height, { limit: PAGE, cursor }), (item) => actionRow(item, { showBlock: false }), 'block.noActions')];
      }, { notFound: 'block.notFound', notFoundValues: { height: shown } })];
  }

  // ------------------------------------------------------------------ action
  function viewAction({ hash }) {
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('action.title') }), h('p', {}, hexNode(hash)),
      part(null, async () => {
        const answer = await api.action(hash), action = answer.action ?? {}, material = answer.verify ?? {};
        const { said, nodes } = describe(action), made = timeOfIso(action.time);
        const fee = { none: 'fee.none', network_fee: 'fee.network', at_most_network_fee: 'fee.atMost' }[action.fee_rule] ?? 'fee.unknown';
        const raw = hexOfBase64(action.raw), payload = action.payload && typeof action.payload === 'object' ? cleanText(JSON.stringify(action.payload, null, 1), 20000, { lines: true }) : null;
        const result = h('div', { class: 'check-result', attrs: { 'aria-live': 'polite' } });
        const button = h('button', { attrs: { type: 'button' }, text: t('check.button') });
        let busy = false;
        button.addEventListener('click', () => {
          if (busy) return;
          const token = generation;
          busy = true; button.setAttribute('aria-busy', 'true');
          result.replaceChildren(state('loading', 'check.running'));
          track(checker.checkAction(hash).then((checked) => { if (token === generation) result.replaceChildren(checkedAction(checked, action)); }, (failure) => { if (token === generation) result.replaceChildren(checkFailureBox(failure)); })
            .finally(() => { busy = false; button.setAttribute('aria-busy', 'false'); }));
        });
        return [h('p', { class: `sentence lead kind-${said.category}` }, nodes), said.status ? h('p', { class: 'status', text: t(said.status) }) : null, indexSource(answer),
          facts([
            ['action.block', blockLink(action.height)],
            ['action.position', Number.isInteger(action.index) && isMicros(String(material.total ?? '')) ? h('span', { text: t('action.positionValue', { position: action.index + 1, total: formatNumber(String(material.total), words) }) }) : missing()],
            ['action.time', made === null ? missing() : [timeNode(made), ' (', agoNode(made), ')']],
            ['action.sender', action.sender === null ? h('span', { text: t('account.nobody') }) : accountLink(action.sender)],
            action.nonce !== null ? ['action.nonce', numberNode(action.nonce)] : null,
            ['action.kind', Number.isInteger(action.kind) && action.kind >= 0 && action.kind <= 255 ? h('span', { text: t('action.kindValue', { kind: action.kind }) }) : missing()],
            ['action.fee', [h('span', { text: t(fee) }), isMicros(action.fee_micros) && action.fee_rule === 'network_fee' ? [': ', amountNode(action.fee_micros)] : null]],
            ['action.results', h('span', { text: t(action.results_checked === true ? 'action.resultsYes' : 'action.resultsNo') })],
          ]),
          said.details.length ? h('details', {}, h('summary', { text: t('action.more') }), facts(said.details.map(({ label, value }) => [label, valueNode(value)]))) : null,
          Number.isInteger(action.repeated) && action.repeated > 1 ? h('p', { class: 'status', text: t('action.repeated', { count: action.repeated }) }) : null,
          h('section', { class: 'part check-part' }, h('h2', { text: t('check.title') }), h('p', { text: t('check.intro') }), button, result),
          h('details', {}, h('summary', { text: t('action.raw') }),
            h('p', { text: t('action.rawHex') }), raw === null ? missing() : h('pre', { class: 'chain-text raw', attrs: { 'aria-label': t('quoted.data') }, text: raw }),
            payload ? [h('p', { text: t('action.payload') }), h('pre', { class: 'chain-text raw', attrs: { 'aria-label': t('quoted.data') }, text: payload.cut ? `${payload.text}…` : payload.text })] : null)];
      }, { notFound: 'action.notFound' })];
  }
  /// The result of a passed check: what it proves, what it does not, and what the proven bytes say.
  function checkedAction(checked, indexed) {
    // The checker hands over checked values; they are still shown only in the forms this page knows.
    const values = { height: formatNumber(checked.height, words) ?? '?', position: Number.isSafeInteger(checked.index) && checked.index >= 0 ? checked.index + 1 : '?', anchor: formatNumber(checked.anchorHeight ?? checked.height, words) ?? '?' };
    const differing = checked.action ? differences(indexed, checked.action) : [];
    return h('div', { class: 'check ok' },
      h('p', { class: 'verdict', text: t('check.ok', values) }),
      h('h3', { text: t('check.bytesSay') }),
      checked.action ? h('p', { class: 'sentence' }, describe(checked.action).nodes) : h('p', { text: t('check.bytesUnread') }),
      checked.action ? (differing.length ? h('p', { class: 'verdict bad', attrs: { role: 'alert' }, text: t('check.differs', { fields: differing.map((field) => t(`field.${field}`)).join(', ') }) }) : h('p', { text: t('check.same') })) : null,
      h('h3', { text: t('check.proves') }),
      h('ul', {}, h('li', { text: t('check.proves1', values) }), h('li', { text: t('check.proves2', values) }),
        h('li', { text: t(!checked.resultsChecked ? 'check.proves3Pending' : checked.mode === 'history' ? 'check.proves3History' : 'check.proves3Own', values) })),
      h('h3', { text: t('check.not') }),
      h('ul', {}, h('li', { text: t('check.not1') }), h('li', { text: t('check.not2') }), h('li', { text: t('check.not3') })));
  }

  // ------------------------------------------------------------------ account
  const roleOf = (device) => (device?.can_manage === true && device?.can_spend === true ? 'all' : device?.can_manage === true ? 'recover' : device?.can_spend === true ? 'spend' : 'signin');
  function viewAccount(route) {
    const byId = route.id !== undefined;
    return [h('h1', { attrs: { tabindex: '-1' }, text: byId ? t('account.title', { id: route.id }) : t('account.titleName') }), byId ? null : h('p', {}, nameNode(route.name)),
      part(null, async () => {
        let read;
        try { read = await readState(() => api.account(route), byId ? { ids: [route.id] } : { names: [route.name] }); } catch (error) { return refusedOr(error, (other) => { throw other; }); }
        const { checked, body, failure } = read;
        // Only the proven state is shown as checked; the service's own copy of the account is
        // used when, and only when, the page could not check.
        const account = checked ? (checked.found ? checked.state.accounts?.find((item) => (byId ? item?.id === route.id : item?.name === route.name)) : null) : body?.account;
        if (!account || !isAccountId(account.id) || (byId ? account.id !== route.id : account.name !== route.name)) {
          if (checked) return [state('empty', 'account.notFoundChecked', { height: formatNumber(checked.height, words) ?? '?' }), stateNote(checked, null)];
          throw new ApiFailure('http', { status: 404 });
        }
        const id = account.id, devices = Array.isArray(account.devices) ? account.devices.slice(0, 64) : [];
        const totals = body?.indexed?.totals ?? {};
        return [facts([
          ['account.name', nameNode(account.name)],
          ['account.id', numberNode(id)],
          ['account.balance', amountNode(account.balance)],
          ['account.nonce', numberNode(account.nonce)],
          ['account.keys', devices.length ? [h('ul', { class: 'keys' }, devices.map((device) => h('li', {}, h('span', { class: 'role', text: `${t(`role.${roleOf(device)}`)}: ` }), isKey(device?.public_key) ? hexNode(device.public_key) : missing()))), h('small', { class: 'source', text: t('account.keysNote') })] : h('span', { text: t('account.noKeys') })],
        ]), stateNote(checked, failure),
        part(t('account.security'), () => loadSecurity(id).catch((error) => refusedOr(error, (other) => { throw other; }))),
        h('section', { class: 'part' }, h('h2', { text: t('account.totals') }), facts([
          ['account.sent', fill('account.totalsValue', { amount: amountNode(totals.sent_micros), count: numberNode(totals.payments_sent) })],
          ['account.received', fill('account.totalsValue', { amount: amountNode(totals.received_micros), count: numberNode(totals.payments_received) })],
        ]), h('small', { class: 'source', text: `${t('source.index')} ${t('account.totalsNote')}` })),
        pagedList(t('account.activity'), (cursor) => api.activity(id, { limit: PAGE, cursor }), (item) => actionRow(item), 'account.noActivity')];
      }, { notFound: 'account.notFound' })];
  }
  /// Whether the account is frozen or has something waiting, and what it has staked: from one
  /// proof of its security row, its stake and its validator.
  async function loadSecurity(id) {
    const { checked, body, failure } = await readState(() => api.accountState(id), { ids: [id], owners: [id], candidates: [id], include_security: true });
    const view = checked ? { security: (checked.state.security ?? []).find((row) => row?.account === id) ?? null, recovery: (checked.state.recovery_cases ?? []).filter((item) => item?.target === id), stake: checked.state.stake_owners?.[id] ?? null, validator: checked.state.candidates?.[id] ?? null, genesis: checked.state.genesis?.genesis_time_micros, at: checked.state.time_micros }
      : { security: body?.security ?? null, recovery: Array.isArray(body?.recovery_cases) ? body.recovery_cases : [], stake: body?.stake ?? null, validator: body?.validator ?? null, genesis: body?.genesis_time_micros, at: body?.state_time_micros };
    const { security, stake, validator } = view;
    const elapsed = isMicros(view.genesis) && isMicros(view.at) && BigInt(view.at) >= BigInt(view.genesis) ? BigInt(view.at) - BigInt(view.genesis) : null;
    /// A moment the state gives as time since the start of the network.
    const moment = (value) => (isMicros(value) && isMicros(view.genesis) ? timeNode(timeOfMicros((BigInt(value) + BigInt(view.genesis)).toString())) : missing());
    const waiting = [];
    let frozen = h('span', { text: t('account.notFrozen') });
    if (security && typeof security === 'object') {
      const replacement = security.pending_root && typeof security.pending_root === 'object' ? security.pending_root : null;
      if (elapsed !== null && isMicros(security.frozen_until_elapsed_micros) && elapsed < BigInt(security.frozen_until_elapsed_micros)) frozen = h('strong', {}, fill('account.frozenUntil', { time: moment(security.frozen_until_elapsed_micros) }));
      else if (replacement && elapsed !== null && isMicros(replacement.expires_elapsed_micros) && BigInt(replacement.expires_elapsed_micros) >= elapsed) frozen = h('strong', { text: t('account.frozenReplacement') });
      if (replacement) waiting.push(fill('account.waitingReplacement', { time: moment(replacement.ready_elapsed_micros) }));
      for (const payment of Array.isArray(security.pending_payments) ? security.pending_payments.slice(0, 32) : []) waiting.push(fill('account.waitingPayment', { amount: amountNode(payment?.amount), to: accountLink(payment?.to), time: moment(payment?.ready_elapsed_micros) }));
      if (security.pending_limit && typeof security.pending_limit === 'object') waiting.push(fill('account.waitingLimit', { amount: amountNode(security.pending_limit.daily_limit_micros), time: moment(security.pending_limit.ready_elapsed_micros) }));
    }
    if (view.recovery.length) waiting.push([t('account.waitingRecovery')]);
    const staked = [];
    if (validator && typeof validator === 'object' && isMicros(validator.self_bond)) staked.push(fill('account.ownValidator', { amount: amountNode(validator.self_bond) }));
    for (const position of Array.isArray(stake?.positions) ? stake.positions.slice(0, 32) : []) {
      // A position is worth its share of the validator's pool. The pool is in this proof only for
      // the account's own validator; for others the shares are shown as they are.
      const pool = position?.candidate === id && validator && isMicros(validator.pool_assets) && isMicros(validator.pool_shares) && BigInt(validator.pool_shares) > 0n && isMicros(position.shares) ? ((BigInt(position.shares) * BigInt(validator.pool_assets)) / BigInt(validator.pool_shares)).toString() : null;
      staked.push(fill(pool === null ? 'account.position' : 'account.positionValued', { shares: numberNode(position?.shares), validator: accountLink(position?.candidate), amount: pool === null ? null : amountNode(pool) }));
    }
    if (Array.isArray(stake?.exits) && stake.exits.length) staked.push([t('account.exits', { count: stake.exits.length })]);
    const policy = security?.policy && typeof security.policy === 'object' ? security.policy : null;
    return [facts([
      ['account.frozen', frozen],
      policy ? ['account.dailyLimit', amountNode(policy.daily_limit_micros)] : null,
      policy && isMicros(policy.delay_seconds) && BigInt(policy.delay_seconds) < 18446744073709n ? ['account.delay', amountNode((BigInt(policy.delay_seconds) * 1000000n).toString())] : null,
      ['account.waiting', waiting.length ? h('ul', {}, waiting.map((nodes) => h('li', {}, nodes))) : h('span', { text: t('account.nothingWaiting') })],
      ['account.stake', staked.length ? h('ul', {}, staked.map((nodes) => h('li', {}, nodes))) : h('span', { text: t('account.noStake') })],
    ]), security ? null : h('p', { text: t('account.plain') }), stateNote(checked, failure)];
  }

  // ------------------------------------------------------------------ validators
  function viewValidators() {
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('validators.title') }), h('p', { text: t('validators.intro') }),
      part(t('validators.now'), async () => {
        let read;
        try { read = await readState(() => api.validators(), { include_pos: true }); } catch (error) { return refusedOr(error, (other) => { throw other; }); }
        const { checked, body, failure } = read;
        const pos = checked ? checked.state.pos : body?.pos, upgrade = checked ? checked.state.upgrade : body?.upgrade, version = checked ? checked.state.protocol_version : body?.protocol_version;
        const genesis = checked ? checked.state.genesis?.genesis_time_micros : null, height = checked ? checked.height : body?.state_height;
        if (!pos || typeof pos !== 'object') return [state('empty', 'validators.noRow'), stateNote(checked, failure)];
        const active = (Array.isArray(pos.active) ? pos.active.slice(0, 200) : []).filter((row) => row && isMicros(row.power)).sort((a, b) => (BigInt(b.power) > BigInt(a.power) ? 1 : BigInt(b.power) < BigInt(a.power) ? -1 : 0));
        const total = active.reduce((sum, row) => sum + BigInt(row.power), 0n).toString();
        const table = active.length ? h('div', { class: 'scroll' }, h('table', {}, h('caption', { text: t('validators.caption', { height: formatNumber(String(height ?? ''), words) ?? '?' }) }),
          h('thead', {}, h('tr', {}, ['validators.account', 'validators.share', 'validators.power', 'validators.key'].map((key) => h('th', { attrs: { scope: 'col' }, text: t(key) })))),
          h('tbody', {}, active.map((row) => h('tr', {}, h('th', { attrs: { scope: 'row' } }, accountLink(row.owner)), h('td', { text: t('percent', { value: formatShare(row.power, total, words) ?? '?' }) }), h('td', {}, numberNode(row.power)), h('td', {}, isKey(row.consensus_key) ? hexNode(row.consensus_key) : missing())))))) : state('empty', 'validators.none');
        const scheduled = Array.isArray(pos.scheduled) ? pos.scheduled.length : 0;
        const plan = upgrade && typeof upgrade === 'object' ? (upgrade.plan && typeof upgrade.plan === 'object' ? upgrade.plan : upgrade.scheduled && typeof upgrade.scheduled === 'object' ? upgrade.scheduled : null) : null;
        const raw = upgrade && typeof upgrade === 'object' ? cleanText(JSON.stringify(upgrade, null, 1), 4000, { lines: true }) : null;
        return [table, active.length ? h('p', { text: t('validators.total', { count: active.length, power: formatNumber(total, words) }) }) : null, stateNote(checked, failure),
          h('section', { class: 'part' }, h('h2', { text: t('validators.changes') }), h('p', { text: scheduled ? t('validators.someChanges', { count: scheduled }) : t('validators.noChanges') }), pos.safety_hold === true ? h('p', { class: 'status', text: t('validators.hold') }) : null),
          h('section', { class: 'part' }, h('h2', { text: t('validators.upgrade') }),
            plan ? [h('p', { class: 'status', text: t('validators.upgradePlan') }), facts([
              ['validators.upgradeVersion', numberNode(plan.version)],
              ['validators.upgradeStart', isMicros(plan.activate_elapsed_micros) && isMicros(genesis) ? timeNode(timeOfMicros((BigInt(plan.activate_elapsed_micros) + BigInt(genesis)).toString())) : missing()],
              ['validators.upgradeSpec', hexNode(typeof plan.spec === 'string' && /^[0-9a-f]{64}$/.test(plan.spec) ? plan.spec : null)],
            ])] : h('p', { text: upgrade === undefined || upgrade === null ? t('validators.noUpgradeRow', { version: typeof version === 'string' && /^[0-9]{1,6}$/.test(version) ? version : '?' }) : t('validators.noUpgrade') }),
            raw ? h('details', {}, h('summary', { text: t('validators.upgradeRaw') }), h('pre', { class: 'chain-text raw', attrs: { 'aria-label': t('quoted.data') }, text: raw.cut ? `${raw.text}…` : raw.text })) : null)];
      })];
  }

  // ------------------------------------------------------------------ a number that may be a block or an account
  function viewFind({ number }) {
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('find.title', { number }) }), h('p', { text: t('find.text') }),
      part(t('find.block', { number }), async () => { const answer = await api.block(number); return [h('p', {}, fill('find.blockFound', { link: blockLink(number), time: agoNode(timeOfMicros(answer.block?.time_micros)) })), indexSource(answer)]; }, { notFound: 'find.noBlock', notFoundValues: { number } }),
      part(t('find.account', { number }), async () => {
        const answer = await api.account({ id: number }), name = answer.account?.name;
        return [h('p', {}, isName(name) ? fill('find.accountNamed', { link: accountLink(number), name: nameNode(name) }) : fill('find.accountFound', { link: accountLink(number) })), source('source.service')];
      }, { notFound: 'find.noAccount', notFoundValues: { number } })];
  }

  // ------------------------------------------------------------------ the frame
  async function loadStatus() {
    const status = await api.status();
    lastStatus = status;
    checker.expectNetwork(status?.network?.network_id);
    drawFrame();
    return status;
  }
  /// The strip that says which network this is, the state of the index, and what the page trusts.
  function drawFrame(failed = false) {
    const network = lastStatus?.network ?? {}, indexer = lastStatus?.indexer ?? {};
    $('network-name').replaceChildren(...(typeof network.chain_id === 'string' ? [quoted(network.chain_id, t('quoted.chain'), 60)] : []));
    const notes = [];
    if (failed && !lastStatus) notes.push(t('index.statusFailed'));
    if (indexer.fault) notes.push(t('index.fault'));
    const made = timeOfIso(indexer.indexed_block_time);
    if (Number.isFinite(indexer.seconds_behind) && indexer.seconds_behind > 120 && made !== null) notes.push(t('index.behind', { ago: agoText(made) }));
    const mismatch = trustInfo && typeof network.network_id === 'string' && network.network_id !== trustInfo.networkId;
    if (mismatch) notes.push(t('trust.mismatch'));
    $('index-note').replaceChildren(...notes.map((text) => h('p', { text })));
    $('index-note').hidden = notes.length === 0;
    $('trust-body').replaceChildren(...(trustInfo
      ? [h('p', { text: t('trust.text') }), facts([['trust.networkId', hexNode(trustInfo.networkId)], ['trust.anchor', trustInfo.anchorHeight ? [h('span', { text: `${t('trust.anchorValue', { height: formatNumber(trustInfo.anchorHeight, words) })} ` }), hexNode(trustInfo.anchorHash)] : h('span', { text: t('trust.anchorGenesis') })]])]
      : [h('p', { text: t('trust.none') })]));
  }
  function render() {
    generation += 1;
    for (const cleanup of cleanups.splice(0)) cleanup();
    refreshers = []; pending = [];
    const route = parseRoute(window.location.hash), view = $('view');
    const nodes = route.view === 'home' ? viewHome() : route.view === 'block' ? viewBlock(route) : route.view === 'action' ? viewAction(route) : route.view === 'account' ? viewAccount(route)
      : route.view === 'validators' ? viewValidators() : route.view === 'find' ? viewFind(route)
      : [h('h1', { attrs: { tabindex: '-1' }, text: t('unknown.title') }), h('p', { text: t('unknown.text') }), h('p', {}, link({ view: 'home' }, t('page.home')))];
    view.replaceChildren(...nodes.flat(3).filter(Boolean));
    for (const [id, name] of [['nav-home', 'home'], ['nav-validators', 'validators']]) { if (route.view === name) $(id).setAttribute('aria-current', 'page'); else $(id).removeAttribute('aria-current'); }
    document.title = t('page.title');
    // After a move inside the page the heading of the new view takes the focus, so that a keyboard
    // or screen reader continues there. On the first load the focus is left where the browser put it.
    if (shown) nodes[0]?.focus?.();
    shown = true;
    if (route.view !== 'home') track(loadStatus().catch(() => drawFrame(true)));
    return settled();
  }
  /// Resolves when everything the current view started has finished (for tests).
  async function settled() { for (let seen = -1; seen !== pending.length;) { seen = pending.length; await Promise.allSettled(pending); } }
  const refresh = () => { for (const update of refreshers) update(); };

  return {
    /// Fills the fixed parts of the page, wires the search box and the two switches, and shows
    /// the view the address names.
    async start() {
      for (const [id, key] of Object.entries(STATIC_TEXT)) $(id).textContent = t(key);
      // The skip link moves the focus to the content without changing the address of the view.
      $('skip-link').addEventListener('click', (event) => { event.preventDefault(); $('view').focus(); });
      $('search-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const found = parseSearch($('search-input').value), route = routeOfSearch(found), error = $('search-error');
        error.textContent = found.kind === 'invalid' ? t(found.reason) : '';
        error.hidden = found.kind !== 'invalid';
        if (route) { $('search-input').value = ''; const href = hrefOf(route); if (window.location.hash === href) render(); else window.location.hash = href; }
      });
      for (const [id, name] of [['toggle-exact', 'exact'], ['toggle-utc', 'utc']]) {
        $(id).setAttribute('aria-pressed', 'false');
        $(id).addEventListener('click', () => { prefs[name] = !prefs[name]; $(id).setAttribute('aria-pressed', String(prefs[name])); refresh(); });
      }
      window.addEventListener('hashchange', () => { render(); });
      tick = timers.setInterval(refresh, 5000);
      trustInfo = await checker.trust().catch(() => null);
      drawFrame();
      return render();
    },
    render, settled,
    stop() { generation += 1; for (const cleanup of cleanups.splice(0)) cleanup(); if (tick !== null) timers.clearInterval(tick); },
  };
}
