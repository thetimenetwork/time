// The explorer's pages: home, block, action, account, validators. One page with addressable
// views (route.mjs). Everything it shows comes from the API (client.mjs) and is treated as
// written by an attacker: values pass a test of format.mjs before use, elements are made by
// dom.mjs only, and what the page has checked itself (check.mjs) is told apart from the index.
//
// What the page calls "checked" is decided by the verified result alone. After a proof has
// verified, nothing else the service said (the status of its answer, its own copy of an account,
// its description of an action) decides what is stated as checked; and once a proof was offered
// and did not pass, the figures it came with are not shown at all.
//
// Where a figure comes from is said before the figure. Figures of the state that the page did
// not check carry the words "Not checked" in front of each of them, so that they cannot be taken
// for checked ones by their look or by a screen reader.
import { createDom } from './dom.mjs';
import { ApiFailure } from './client.mjs';
import { CheckFailure } from './check.mjs';
import { describeAction, compareAction } from './describe.mjs';
import { parseRoute, parseSearch, routeOfSearch, hrefOf, newPager, pagerLoaded, pagerCursor, pagerNext, pagerPrevious, canNext, canPrevious } from './route.mjs';
import { isHash, isHeight, isAccountId, isMicros, isName, isKey, isCount, isReference, cleanText, formatAmount, formatMicros, formatNumber, formatShare, formatTime, timeOfMicros, timeOfIso, ago, shortHex, hexOfBase64, hexLines, readJoin } from './format.mjs';

const PAGE = 25, HOME_ROWS = 10, HOME_SCAN = 50;
/// The fixed parts of index.html and the entry of the strings table each one shows.
export const STATIC_TEXT = Object.freeze({
  'skip-link': 'page.skip', 'brand': 'page.brand', 'network-warning': 'page.warning', 'nav-home': 'page.home', 'nav-validators': 'page.validators', 'search-label': 'page.searchLabel', 'search-button': 'page.searchButton',
  'toggle-exact': 'page.exact', 'toggle-utc': 'page.utc', 'legend-title': 'page.legend', 'legend-index': 'page.legendIndex', 'legend-checked': 'page.legendChecked', 'legend-unchecked': 'page.legendUnchecked', 'legend-quoted': 'page.legendQuoted', 'trust-title': 'trust.title', 'boot-note': 'page.boot',
});
const FEES = new Map([['none', 'fee.none'], ['network_fee', 'fee.network'], ['at_most_network_fee', 'fee.atMost']]);
const CHECK_REASONS = ['refused', 'silent', 'no_trust', 'wrong_network', 'no_verifier', 'trust_expired', 'clock', 'unavailable', 'behind', 'too_new', 'not_kept', 'upgrade_required', 'network_reset'];
/// A whole number small enough to stand in one of the page's own sentences.
const smallCount = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
const plain = (value) => (value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null);

/// `loadJoin` (optional) reads the page's join.json: it resolves to the text of the file, or to null when none
/// was installed with the page, and throws when it could not be read now.
export function createExplorer({ document, window, api, checker, live = null, t, now = Date.now, timers = globalThis, locale, timeZone, loadJoin = null }) {
  const { h, quoted, sentence } = createDom(document);
  const $ = (id) => document.getElementById(id);
  const words = { h: t('unit.h'), min: t('unit.min'), s: t('unit.s'), micros: t('unit.micros'), thousands: t('unit.thousands'), decimal: t('unit.decimal') };
  const prefs = { exact: false, utc: false };
  /// Whether the page reads the API at the origin it was served from: the service then supplied
  /// the page and its trusted block too, and the page says so wherever it speaks of trust.
  const sameOrigin = !api.origin;
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
  /// A name read from the verified state ("from the chain"), and one the service gave unchecked.
  const nameNode = (name) => (isName(name) ? quoted(`@${name}`, t('quoted.name')) : missing());
  const serviceName = (name) => (isName(name) ? quoted(`@${name}`, t('quoted.serviceName')) : missing());
  const kindNode = (kind) => (Number.isInteger(kind) && kind >= 0 && kind <= 255 ? h('span', { text: t('action.kindValue', { kind }) }) : missing());
  const senderNode = (sender) => (sender === null || sender === undefined ? h('span', { text: t('account.nobody') }) : accountLink(sender));
  /// "number 2 of 5": only from a position and a count that are small whole numbers.
  const positionNode = (index, total) => (!smallCount(index, 99999) ? missing() : isMicros(String(total ?? '')) ? h('span', { text: t('action.positionValue', { position: index + 1, total: formatNumber(String(total), words) }) }) : h('span', { text: t('action.positionOnly', { position: index + 1 }) }));
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
      case 'hash': return isKey(value.hex) ? hexNode(value.hex) : missing();
      // A moment given as time since the start of the network: a date when the page's trust
      // manifest holds the start time, otherwise the time since the start, said as that.
      case 'sinceStart': {
        if (!isMicros(value.micros)) return missing();
        const genesis = trustInfo?.genesisTimeMicros ?? null;
        return genesis !== null && isMicros(String(genesis)) ? timeNode(timeOfMicros((BigInt(value.micros) + BigInt(genesis)).toString())) : h('span', {}, sentence(t('value.sinceStart'), { amount: amountNode(value.micros) }));
      }
      default: return missing();
    }
  }
  const fill = (key, parts) => sentence(t(key), parts);
  const describe = (action) => { const said = describeAction(action); return { said, nodes: fill(said.sentence, Object.fromEntries(Object.entries(said.params).map(([name, value]) => [name, valueNode(value)]))) }; };
  /// Where what follows comes from. It stands before the figures it speaks of.
  const source = (key, values) => h('small', { class: 'source', text: t(key, values) });
  const indexSource = (answer) => (isHeight(answer?.index?.indexed_height) ? source('source.indexAt', { height: formatNumber(answer.index.indexed_height, words) }) : source('source.index'));
  /// The words that stand in front of every figure of the state the page did not check.
  const uncheckedTag = () => h('strong', { class: 'tag unchecked', text: t('tag.unchecked') });
  const facts = (rows, { unchecked = false } = {}) => h('dl', { class: unchecked ? 'facts unchecked' : 'facts' }, rows.filter(Boolean).map(([label, value]) => [h('dt', { text: t(label) }), h('dd', {}, unchecked ? [uncheckedTag(), ' '] : null, value)]));
  const state = (className, key, values) => h('p', { class: `state ${className}`, text: t(key, values) });
  /// A completed waiting payment as the index lists it: its recipient and amount are the index's
  /// attribution, which the bytes of the action do not carry. Said wherever such a line stands.
  const attributed = (item) => (item?.kind === 75 && item?.transfers === true ? h('p', { class: 'status', text: t('action.attributed') }) : null);

  // ------------------------------------------------------------------ loading, failing, retrying
  /// What to show for a request that failed. For a failure that can pass (no connection, a rate
  /// limit, a busy service) the part is loaded again by itself after the wait the service asked
  /// for, a few times.
  function failureBox(error, { notFound = 'error.notFound', notFoundValues, retry, auto }) {
    const failure = error instanceof CheckFailure && error.detail instanceof ApiFailure ? error.detail : error;
    let key = 'error.page', values, passing = false;
    if (failure instanceof ApiFailure) {
      // From another origin a browser reports a refusal by the service's origin list as a failed connection.
      if (failure.kind === 'network') { key = sameOrigin ? 'error.network' : 'error.networkElsewhere'; passing = true; }
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
      const seconds = Math.min(300, Math.max(2, failure instanceof ApiFailure && failure.retryAfter ? failure.retryAfter : 5));
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
      return [indexSource(answer), items.length ? h('ul', { class: 'rows' }, items.map(row)) : state('empty', emptyKey), pages];
    });
  }
  /// One action in a list: what it did, when, and the way to its own page.
  function actionRow(item, { showBlock = true } = {}) {
    const { said, nodes } = describe(item), made = timeOfIso(item?.time);
    return h('li', { class: `row kind-${said.category}` }, h('p', { class: 'sentence' }, nodes),
      attributed(item),
      said.status ? h('p', { class: 'status', text: t(said.status) }) : null,
      item?.role === 'pending' ? h('p', { class: 'status', text: t('account.role.pending') }) : null,
      h('p', { class: 'meta' }, made === null ? null : [agoNode(made), ' · '], showBlock && isHeight(item?.height) ? [blockLink(item.height), ' · '] : null, actionLink(item?.hash, t('action.details'))));
  }
  const countText = (count) => (count === 0 ? t('actions.count.none') : count === 1 ? t('actions.count.one') : t('actions.count.many', { count: formatNumber(count, words) }));

  // ------------------------------------------------------------------ what was checked
  /// Why a check gave no result, in the page's words, with the technical text set apart. The
  /// text of the verifier is announced as that: it is not the service's, though it may quote it.
  function checkFailureBox(failure) {
    const reason = CHECK_REASONS.includes(failure?.reason) ? failure.reason : 'unavailable';
    const bad = reason === 'refused' || reason === 'silent';
    const box = h('div', { class: bad ? 'check bad' : 'check unknown', attrs: { role: bad ? 'alert' : 'status' } }, h('p', { class: 'verdict', text: t(`check.${reason}`) }));
    const said = failure?.detail instanceof ApiFailure ? failure.detail.code ?? (failure.detail.status ? String(failure.detail.status) : failure.detail.kind) : null;
    const own = typeof failure?.detail === 'string' && failure.detail ? failure.detail : null;
    if (said) box.append(h('details', {}, h('summary', { text: t('check.detail') }), quoted(said, t('quoted.service'), 60)));
    // The text of a verifier that did not load is the browser's; any other is the verifier's own.
    else if (own) box.append(h('details', {}, h('summary', { text: t('check.detail') }), quoted(own, t(reason === 'no_verifier' ? 'quoted.loader' : 'quoted.verifier'), 300)));
    return box;
  }
  /// What stands before figures of the state: that they were checked here (and what that means),
  /// or, in words that cannot be overlooked, that they were not and why.
  function stateNote(checked, failure) {
    if (checked) return h('div', { class: 'check ok' }, h('p', { class: 'origin', text: t('source.checked', { height: formatNumber(checked.height, words) ?? '?' }) }),
      h('details', {}, h('summary', { text: t('check.stateWhat') }), h('p', { text: t(sameOrigin ? 'check.stateTextSame' : 'check.stateText', { anchor: formatNumber(checked.anchorHeight ?? checked.height, words) ?? '?' }) })));
    return h('div', { class: 'check unknown unchecked-note', attrs: { role: 'note' } }, h('p', { class: 'origin' }, h('strong', { text: t('source.service') })), h('details', {}, h('summary', { text: t('account.unchecked') }), checkFailureBox(failure)));
  }
  /// Reads a state through the check. Returns { checked, body, failure }:
  /// - `checked`: the proven state. Only it is shown as checked.
  /// - Otherwise `body` is the service's answer, shown as its word, and `failure` says why the
  ///   page could not check. That happens only when the page had nothing to check with (no trust
  ///   manifest, no verifier, a trusted block that has expired, a clock that does not fit) and
  ///   had therefore not looked at any proof of the service: one request, not a second one.
  /// Everything else throws, and the caller shows no figure: a proof that was offered and did not
  /// pass, for whatever reason; a service that names another network than the page's.
  async function readState(fetchBody, query) {
    try { const checked = await checker.checkState(fetchBody, query); return { checked, body: checked.body, failure: null }; } catch (error) {
      if (!(error instanceof CheckFailure)) throw error;
      if (error.reason === 'unavailable' && error.detail instanceof ApiFailure) throw error.detail;
      if (error.offered !== true && ['no_trust', 'no_verifier', 'trust_expired', 'clock'].includes(error.reason)) return { checked: null, body: await fetchBody(), failure: error };
      throw error;
    }
  }
  /// What stands in the place of figures the page will not show. Any other failure is thrown on,
  /// to be shown as a failed request.
  function withheld(error, reload) {
    if (!(error instanceof CheckFailure)) throw error;
    // The network this page was loaded for was reset: one sentence, and no "Try again" (only a reload helps).
    if (error.reason === 'network_reset') return [h('div', { class: 'check unknown', attrs: { role: 'alert' } }, h('p', { class: 'verdict', text: t('check.network_reset') }))];
    const failed = error.reason === 'refused';
    return [h('div', { class: failed ? 'check bad' : 'check unknown', attrs: { role: 'alert' } }, h('p', { class: 'verdict', text: t(failed ? 'check.stateRefused' : 'check.stateWithheld') }), checkFailureBox(error),
      !failed && reload ? h('button', { class: 'quiet', attrs: { type: 'button' }, on: { click: () => reload() }, text: t('state.retry') }) : null)];
  }
  /// Whether the verified state shows the account that was asked for to be absent: by its number
  /// in the list of absent ones, or by its name mapped to nothing.
  const provenAbsent = (checked, { id, name }) => (id !== undefined ? Array.isArray(checked.absent) && checked.absent.includes(id) : plain(checked.names) !== null && Object.hasOwn(checked.names, name) && checked.names[name] === null);

  // ------------------------------------------------------------------ home
  const cleanBlock = (item) => (item && isHeight(item.height) && isMicros(item.time_micros) && isCount(item.tx_count) ? { height: item.height, made: timeOfMicros(item.time_micros), micros: item.time_micros, count: item.tx_count, payments: isCount(item.payment_count) ? item.payment_count : 0 } : null);
  function viewHome() {
    let blocks = [], payments = [], status = lastStatus, misses = 0, quietUntil = 0;
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
        ['home.networkId', [source('source.serviceSays'), ' ', hexNode(network.network_id)]],
        ['home.height', newest ? [source('source.index'), ' ', numberNode(newest.height)] : h('span', { text: t('home.noBlocks') })],
        newest ? ['home.blockTime', [source('source.index'), ' ', timeNode(newest.made), ' (', agoNode(newest.made), ')']] : null,
        // The fee is the service's word on every load: the home page checks nothing.
        ['home.fee', isMicros(network.fee_micros) ? [uncheckedTag(), ' ', amountNode(network.fee_micros)] : h('span', { text: t('home.feeUnknown') })],
        ['home.issued', issued !== null ? [h('small', { class: 'source', text: t('home.issuedHow') }), ' ', amountNode(issued)] : h('span', { text: t(genesis === null ? 'home.issuedUnknown' : 'home.noBlocks') })],
      ]));
    };
    const addBlock = (item) => { const block = cleanBlock(item); if (!block || blocks.some((known) => known.height === block.height)) return; blocks = [block, ...blocks].sort((a, b) => (BigInt(b.height) > BigInt(a.height) ? 1 : -1)).slice(0, HOME_ROWS); drawBlocks(); drawNetwork(); };
    const addPayment = (item) => { if (!item || !isHash(item.hash) || !isHeight(item.height) || payments.some((known) => known.hash === item.hash)) return; payments = [item, ...payments].slice(0, HOME_ROWS); drawPayments(); };
    async function readLists() {
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
    /// Reads the lists, and after a failure keeps quiet for as long as the service asked, or for
    /// a time that doubles with every failure in a row: the page does not go on asking a service
    /// that has just said "wait".
    const loadLists = () => readLists().then(() => { misses = 0; quietUntil = 0; }, (error) => {
      misses += 1;
      quietUntil = now() + (error instanceof ApiFailure && error.retryAfter ? error.retryAfter * 1000 : Math.min(300000, 10000 * 2 ** misses));
      throw error;
    });
    const setLive = (name) => { liveLine.textContent = t(`live.${['live', 'connecting', 'waiting'].includes(name) ? name : 'idle'}`); };
    if (live) {
      const token = generation;
      live.listen({
        onState: (name) => { if (token === generation) setLive(name); },
        onEvent: ({ type, data }) => {
          if (token !== generation) return;
          if (type === 'block') addBlock(data); else if (type === 'payment') addPayment(data);
          else if (type === 'gap') { if (now() >= quietUntil) track(loadLists().catch(() => {})); liveLine.textContent = t('live.gap'); }
        },
      });
      live.start();
      // While the stream is down the lists are read again from time to time: not in a tab nobody
      // looks at, and not before a wait the service asked for is over.
      const poll = timers.setInterval(() => { if (token === generation && live.state() !== 'live' && document.hidden !== true && now() >= quietUntil) track(loadLists().catch(() => {})); }, 10000);
      cleanups.push(() => { timers.clearInterval(poll); live.stop(); });
      setLive(live.state());
    } else setLive('idle');
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('home.title') }),
      part(t('home.network'), async () => { status = await loadStatus(); drawNetwork(); return networkBody; }),
      part(t('home.blocks'), async () => { await loadLists(); return [source('source.index'), blockList, liveLine]; }),
      h('section', { class: 'part' }, h('h2', { text: t('home.payments') }), h('small', { class: 'source', text: `${t('source.index')} ${t('home.paymentsNote', { count: HOME_SCAN })}` }), paymentList)];
  }

  // ------------------------------------------------------------------ block
  function viewBlock({ height }) {
    const shownHeight = formatNumber(height, words);
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('block.title', { height: shownHeight }) }),
      part(null, async () => {
        const answer = await api.block(height), block = plain(answer.block) ?? {};
        const made = timeOfMicros(block.time_micros), previous = (BigInt(height) - 1n).toString(), next = (BigInt(height) + 1n).toString();
        const more = isHeight(answer.index?.indexed_height) && BigInt(answer.index.indexed_height) > BigInt(height);
        return [indexSource(answer), facts([
          ['block.height', numberNode(height)],
          ['block.time', [timeNode(made), ' (', agoNode(made), ')']],
          ['block.hash', hexNode(isHash(block.hash) ? block.hash : null)],
          ['block.count', isCount(block.tx_count) ? h('span', { text: countText(block.tx_count) }) : missing()],
          ['block.payments', numberNode(block.payment_count)],
          ['block.proposer', hexNode(typeof block.proposer === 'string' && /^[0-9A-Fa-f]{40}$/.test(block.proposer) ? block.proposer : null)],
          ['block.results', h('span', { text: t(block.results_checked === true ? 'block.resultsYes' : 'block.resultsNo') })],
          isHeight(previous) ? ['block.previous', blockLink(previous)] : null,
          more ? ['block.next', blockLink(next)] : null,
        ]),
        pagedList(t('block.actions'), (cursor) => api.blockActions(height, { limit: PAGE, cursor }), (item) => actionRow(item, { showBlock: false }), 'block.noActions')];
      }, { notFound: 'block.notFound', notFoundValues: { height: shownHeight } })];
  }

  // ------------------------------------------------------------------ action
  /// What only the index says of an action, before and after a check: its time, fee and result.
  function indexRows(action) {
    const made = timeOfIso(action.time);
    return [
      ['action.time', made === null ? missing() : [timeNode(made), ' (', agoNode(made), ')']],
      ['action.fee', [h('span', { text: t(FEES.get(action.fee_rule) ?? 'fee.unknown') }), isMicros(action.fee_micros) && action.fee_rule === 'network_fee' ? [': ', amountNode(action.fee_micros)] : null]],
      ['action.results', h('span', { text: t(action.results_checked === true ? 'action.resultsYes' : 'action.resultsNo') })],
    ];
  }
  const moreDetails = (said) => (said.details.length ? h('details', {}, h('summary', { text: t('action.more') }), facts(said.details.map(({ label, value }) => [label, valueNode(value)]))) : null);
  /// The action as the service describes it: the index's word, and marked as that before it.
  function servedDescription(answer, action, material) {
    const { said, nodes } = describe(action), [time, fee, results] = indexRows(action);
    return [indexSource(answer), h('p', { class: `sentence lead kind-${said.category}` }, nodes), attributed(action), said.status ? h('p', { class: 'status', text: t(said.status) }) : null,
      facts([
        ['action.block', blockLink(action.height)],
        ['action.position', positionNode(action.index, material.total)],
        time,
        ['action.sender', senderNode(action.sender)],
        action.nonce !== null && action.nonce !== undefined ? ['action.nonce', numberNode(action.nonce)] : null,
        ['action.kind', kindNode(action.kind)],
        fee, results,
      ]),
      moreDetails(said)];
  }
  /// The action after a passed check: the sentence, the facts and the details are built anew from
  /// the checked bytes and the checked block, and replace the service's. What the bytes cannot
  /// say is shown as the service's word and called unconfirmed, next to the fact it concerns.
  function provenDescription(checked, answer, action) {
    const decoded = plain(checked.action), envelope = plain(checked.envelope);
    const frame = decoded ? { kind: decoded.kind, sender: decoded.from === '18446744073709551615' ? null : decoded.from, nonce: decoded.nonce } : envelope;
    const nodes = [];
    let said = null;
    if (decoded) {
      const read = describe(decoded);
      said = read.said;
      nodes.push(h('p', { class: 'origin', text: t('origin.bytes') }), h('p', { class: `sentence lead kind-${said.category}` }, read.nodes));
      // A completed waiting payment: its bytes hold a number, not who was paid how much.
      if (decoded.kind === 75 && decoded.payload?.type === 'execute' && action.recipient !== null && action.recipient !== undefined) nodes.push(h('p', { class: 'status' }, fill('check.executeUnconfirmed', { to: accountLink(action.recipient), amount: amountNode(action.amount) })));
      // How a request for a waiting payment ended is known to the index only.
      const status = decoded.kind === 75 && action.kind === 75 ? describeAction(action).status : null;
      if (status) nodes.push(h('p', { class: 'status' }, source('source.index'), ' ', t(status)));
    } else {
      nodes.push(h('p', { class: 'verdict bad', attrs: { role: 'alert' }, text: t(frame ? 'check.contentUnread' : 'check.bytesUnread') }));
      if (frame) nodes.push(h('p', { class: 'sentence lead' }, describe({ kind: frame.kind, opaque: true, sender: frame.sender }).nodes), source('source.bytes'));
      nodes.push(h('p', { text: t('check.serviceSaid') }), h('p', { class: 'sentence unconfirmed' }, describe(action).nodes), source('source.unconfirmed'));
    }
    nodes.push(facts([
      ['action.block', blockLink(checked.height)],
      ['action.position', checked.index === null || checked.index === undefined ? h('span', { text: t('action.positionOpen') }) : positionNode(checked.index, checked.total)],
      frame ? ['action.sender', senderNode(frame.sender)] : null,
      frame ? ['action.nonce', numberNode(frame.nonce)] : null,
      frame ? ['action.kind', kindNode(frame.kind)] : null,
    ]), source('source.bytes'), indexSource(answer), facts(indexRows(action)), said ? moreDetails(said) : null);
    return nodes;
  }
  /// The bytes of an action and their content: the service's, marked as the index's, or after a
  /// passed check the checked ones.
  function rawNodes(hex, payload, checkedBytes) {
    const content = plain(payload) ? cleanText(JSON.stringify(payload, null, 1), 20000, { lines: true }) : null;
    return [checkedBytes ? source('source.bytes') : source('source.index'),
      h('p', { text: t('action.rawHex') }), hex === null ? missing() : h('pre', { class: 'chain-text raw', attrs: { 'aria-label': t('quoted.data') }, text: hex }),
      content ? [h('p', { text: t(checkedBytes ? 'action.payloadChecked' : 'action.payload') }), h('pre', { class: 'chain-text raw', attrs: { 'aria-label': t('quoted.data') }, text: content.cut ? `${content.text}…` : content.text })] : null];
  }
  /// The result of a passed check: whether what the service said held, what the check proves and
  /// what it does not.
  function checkedAction(checked, action) {
    const bound = smallCount(checked.index, 99999);
    const values = { height: formatNumber(checked.height, words) ?? '?', position: bound ? checked.index + 1 : '?', anchor: formatNumber(checked.anchorHeight ?? checked.height, words) ?? '?' };
    const compared = compareAction(action, checked), names = (fields) => fields.map((field) => t(`field.${field}`)).join(', ');
    const lines = [];
    if (compared.differing.length) lines.push(h('p', { class: 'verdict bad', attrs: { role: 'alert' }, text: t('check.differs', { fields: names(compared.differing) }) }));
    if (compared.read !== 'content') lines.push(h('p', { class: 'verdict bad', attrs: { role: 'alert' }, text: t(compared.read === 'frame' ? 'check.frameOnly' : 'check.notCompared') }));
    else if (compared.unconfirmed.length) lines.push(h('p', { class: 'status', text: t('check.partly', { fields: names(compared.unconfirmed) }) }));
    else if (!compared.differing.length) lines.push(h('p', { text: t(bound ? 'check.same' : 'check.sameOpen') }));
    return h('div', { class: 'check ok' },
      h('p', { class: 'verdict', text: t('check.ok', values) }), lines,
      h('h3', { text: t('check.proves') }),
      h('ul', {}, h('li', { text: t(bound ? 'check.proves1' : 'check.proves1Open', values) }), h('li', { text: t('check.proves2', values) }),
        h('li', { text: t(!checked.resultsChecked ? 'check.proves3Pending' : checked.mode === 'history' ? 'check.proves3History' : 'check.proves3Own', values) })),
      h('h3', { text: t('check.not') }),
      h('ul', {}, h('li', { text: t(sameOrigin ? 'check.not1Same' : 'check.not1') }), h('li', { text: t('check.not2') }), h('li', { text: t('check.not3') })));
  }
  function viewAction({ hash }) {
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('action.title') }), h('p', {}, hexNode(hash)),
      part(null, async () => {
        const answer = await api.action(hash), action = plain(answer.action) ?? {}, material = plain(answer.verify) ?? {};
        const described = h('div', { class: 'described' }, servedDescription(answer, action, material));
        const bytes = h('div', { class: 'bytes' }, rawNodes(hexOfBase64(action.raw), action.payload, false));
        const result = h('div', { class: 'check-result', attrs: { 'aria-live': 'polite' } });
        const button = h('button', { attrs: { type: 'button' }, text: t('check.button') });
        let busy = false;
        button.addEventListener('click', () => {
          if (busy) return;
          const token = generation;
          busy = true; button.setAttribute('aria-busy', 'true');
          result.replaceChildren(state('loading', 'check.running'));
          track(checker.checkAction(hash).then((checked) => {
            if (token !== generation) return;
            described.replaceChildren(...provenDescription(checked, answer, action).flat(3).filter(Boolean));
            // The bytes shown are now the checked ones, and their content what this page read from
            // them. If it could not read them, the service's reading stays, called unconfirmed.
            const decoded = plain(checked.action);
            bytes.replaceChildren(...[rawNodes(hexLines(checked.rawHex), decoded?.payload ?? null, true),
              decoded || !plain(action.payload) ? null : [source('source.unconfirmed'), h('p', { text: t('action.payload') }), h('pre', { class: 'chain-text raw', attrs: { 'aria-label': t('quoted.data') }, text: cleanText(JSON.stringify(action.payload, null, 1), 20000, { lines: true }).text })]].flat(3).filter(Boolean));
            result.replaceChildren(checkedAction(checked, action));
          }, (failure) => { if (token === generation) result.replaceChildren(checkFailureBox(failure)); }).finally(() => { busy = false; button.setAttribute('aria-busy', 'false'); }));
        });
        return [described,
          // How often the same bytes are on the chain is something only the index counts.
          smallCount(action.repeated, 1e9) && action.repeated > 1 ? h('p', { class: 'status' }, source('source.index'), ' ', t('action.repeated', { count: formatNumber(action.repeated, words) })) : null,
          h('section', { class: 'part check-part' }, h('h2', { text: t('check.title') }), h('p', { text: t('check.intro') }), button, result),
          h('details', {}, h('summary', { text: t('action.raw') }), bytes)];
      }, { notFound: 'action.notFound' })];
  }

  // ------------------------------------------------------------------ account
  const roleOf = (device) => (device?.can_manage === true && device?.can_spend === true ? 'all' : device?.can_manage === true ? 'recover' : device?.can_spend === true ? 'spend' : 'signin');
  function viewAccount(route) {
    const byId = route.id !== undefined;
    // Until the chain has answered, a name is only what the link says, and is labelled so.
    return [h('h1', { attrs: { tabindex: '-1' }, text: byId ? t('account.title', { id: route.id }) : t('account.titleName') }), byId ? null : h('p', {}, isName(route.name) ? quoted(`@${route.name}`, t('quoted.linkName')) : missing()),
      part(null, async ({ reload }) => {
        let read;
        try { read = await readState(() => api.account(route), byId ? { ids: [route.id] } : { names: [route.name] }); } catch (error) { return withheld(error, reload); }
        const { checked, body, failure } = read;
        let account;
        if (checked) {
          // Whether the account exists is read from the verified state alone: it holds the
          // account, or the proof shows that it does not exist. The status of the service's
          // answer decides nothing, and a proof that says neither answers nothing.
          account = (Array.isArray(checked.state.accounts) ? checked.state.accounts : []).find((item) => (byId ? item?.id === route.id : item?.name === route.name)) ?? null;
          if (!account) {
            if (provenAbsent(checked, route)) return [stateNote(checked, null), state('empty', 'account.notFoundChecked', { height: formatNumber(checked.height, words) ?? '?' })];
            return withheld(new CheckFailure('silent', null, { offered: true }), reload);
          }
          if (!isAccountId(account.id)) return withheld(new CheckFailure('silent', null, { offered: true }), reload);
        } else {
          // Nothing was checked: what follows is the service's word, and an answer that is not in
          // the form of an account is called that, not a proof.
          account = plain(body?.account);
          if (!account || (byId ? account.id !== route.id : account.name !== route.name)) throw new ApiFailure('http', { status: 404 });
          if (!isAccountId(account.id)) return [stateNote(null, failure), state('failed', 'account.unreadable')];
        }
        const id = account.id, devices = Array.isArray(account.devices) ? account.devices.slice(0, 64) : [];
        const totals = plain(body?.indexed?.totals);
        return [stateNote(checked, failure), facts([
          ['account.name', checked ? nameNode(account.name) : serviceName(account.name)],
          ['account.id', numberNode(id)],
          ['account.balance', amountNode(account.balance)],
          ['account.nonce', numberNode(account.nonce)],
          ['account.keys', devices.length ? [h('ul', { class: 'keys' }, devices.map((device) => h('li', {}, h('span', { class: 'role', text: `${t(`role.${roleOf(device)}`)}: ` }), isKey(device?.public_key) ? hexNode(device.public_key) : missing()))), h('small', { class: 'source', text: t('account.keysNote') })] : h('span', { text: t('account.noKeys') })],
        ], { unchecked: !checked }),
        part(t('account.security'), ({ reload: again }) => loadSecurity(id).catch((error) => withheld(error, again))),
        totals ? h('section', { class: 'part' }, h('h2', { text: t('account.totals') }), h('small', { class: 'source', text: `${t('source.index')} ${t(checked ? 'account.totalsNoteChecked' : 'account.totalsNote')}` }), facts([
          ['account.sent', fill('account.totalsValue', { amount: amountNode(totals.sent_micros), count: numberNode(totals.payments_sent) })],
          ['account.received', fill('account.totalsValue', { amount: amountNode(totals.received_micros), count: numberNode(totals.payments_received) })],
        ])) : null,
        pagedList(t('account.activity'), (cursor) => api.activity(id, { limit: PAGE, cursor }), (item) => actionRow(item), 'account.noActivity')];
      }, { notFound: 'account.notFound' })];
  }
  /// The clock the moments of a security row are on. On a network whose genesis has `waits_survive_stops` they are
  /// moments on the clock of the waits: the chain's time less the total of its stops (`stopped_micros`). Compared
  /// with the chain's time, or shown as dates as they stand, they come too early by that total: a freeze looks over
  /// and a payment ready while the chain holds the opposite. Gives { rule, stopped }, or null when what was given is
  /// not in a form a network writes. From a checked state: its configuration and its total. From the service's word:
  /// the `security_clock` the API sends with the row; a service from before sends none, which is read as before.
  const waitsOfState = (state) => {
    const rule = state?.config?.waits_survive_stops, total = state?.stopped_micros;
    if (rule === undefined) return total === undefined ? { rule: false, stopped: 0n } : null;
    return rule === true && isMicros(total) ? { rule: true, stopped: BigInt(total) } : null;
  };
  const waitsOfClock = (clock) => {
    if (clock === undefined || clock === null) return { rule: false, stopped: 0n };
    const said = plain(clock);
    if (said?.waits_survive_stops === true && isMicros(said.stopped_micros)) return { rule: true, stopped: BigInt(said.stopped_micros) };
    return said?.waits_survive_stops === false && said.stopped_micros === '0' ? { rule: false, stopped: 0n } : null;
  };
  /// Whether the account is frozen or has something waiting, and what it has staked: from one
  /// proof of its security row, its recovery cases, its stake and its validator.
  async function loadSecurity(id) {
    const { checked, body, failure } = await readState(() => api.accountState(id), { ids: [id], owners: [id], candidates: [id], include_security: true });
    /// A row the proof was asked about: `known` is false if the verified state does not speak of it.
    const asked = (map) => (plain(map) && Object.hasOwn(map, id) ? { known: true, row: plain(map[id]) } : { known: false, row: null });
    let view;
    if (checked) {
      // The proof must speak of this account and of its security row, or it answers nothing.
      if (!Array.isArray(checked.state.accounts) || !checked.state.accounts.some((item) => item?.id === id) || !Array.isArray(checked.state.security)) throw new CheckFailure('silent', null, { offered: true });
      view = { security: plain(checked.state.security.find((row) => row?.account === id)), recovery: (Array.isArray(checked.state.recovery_cases) ? checked.state.recovery_cases : []).filter((item) => item?.target === id),
        stake: asked(checked.state.stake_owners), validator: asked(checked.state.candidates), genesis: checked.state.genesis?.genesis_time_micros, at: checked.state.time_micros, waits: waitsOfState(checked.state) };
    } else view = { security: plain(body?.security), recovery: Array.isArray(body?.recovery_cases) ? body.recovery_cases : [], stake: { known: true, row: plain(body?.stake) }, validator: { known: true, row: plain(body?.validator) }, genesis: body?.genesis_time_micros, at: body?.state_time_micros, waits: waitsOfClock(body?.security_clock) };
    const { security, waits } = view, stake = view.stake.row, validator = view.validator.row;
    const elapsed = isMicros(view.genesis) && isMicros(view.at) && BigInt(view.at) >= BigInt(view.genesis) ? BigInt(view.at) - BigInt(view.genesis) : null;
    // The clock of the waits: what the moments of the security row are compared with (the chain's time on a network
    // without the setting). Unknown when the total of stops is.
    const clock = elapsed !== null && waits !== null && waits.stopped <= elapsed ? elapsed - waits.stopped : null;
    /// A moment of the security row as a date: the moment plus the stops so far. On a network whose waits survive a
    /// stop, a moment that has not come is the earliest it can come (a later stop moves it), and is said so.
    const moment = (value) => {
      if (!isMicros(value) || !isMicros(view.genesis) || clock === null) return missing();
      const time = timeNode(timeOfMicros((BigInt(value) + waits.stopped + BigInt(view.genesis)).toString()));
      return waits.rule && BigInt(value) > clock ? fill('value.earliest', { time }) : time;
    };
    const waiting = [], replacement = plain(security?.pending_root);
    // The engine refuses the actions of an account while a recovery through its helpers has its
    // approvals and has not expired (v5/src/engine.rs, "frozen by threshold guardian recovery").
    // That rule is on the chain's time on every network.
    const recovering = elapsed !== null && view.recovery.some((item) => item?.ready_elapsed_micros !== null && item?.ready_elapsed_micros !== undefined && isMicros(item?.expires_elapsed_micros) && BigInt(item.expires_elapsed_micros) >= elapsed);
    let frozen;
    if (elapsed === null || clock === null) frozen = missing();
    else if (security && isMicros(security.frozen_until_elapsed_micros) && clock < BigInt(security.frozen_until_elapsed_micros)) frozen = h('strong', {}, fill('account.frozenUntil', { time: moment(security.frozen_until_elapsed_micros) }));
    else if (replacement && isMicros(replacement.expires_elapsed_micros) && BigInt(replacement.expires_elapsed_micros) >= clock) frozen = h('strong', { text: t('account.frozenReplacement') });
    else if (recovering) frozen = h('strong', { text: t('account.frozenRecovery') });
    else frozen = h('span', { text: t('account.notFrozen') });
    if (replacement) waiting.push(fill('account.waitingReplacement', { time: moment(replacement.ready_elapsed_micros) }));
    for (const payment of Array.isArray(security?.pending_payments) ? security.pending_payments.slice(0, 32) : []) waiting.push(fill('account.waitingPayment', { amount: amountNode(payment?.amount), to: accountLink(payment?.to), time: moment(payment?.ready_elapsed_micros) }));
    if (plain(security?.pending_limit)) waiting.push(fill('account.waitingLimit', { amount: amountNode(security.pending_limit.daily_limit_micros), time: moment(security.pending_limit.ready_elapsed_micros) }));
    if (view.recovery.length) waiting.push([t('account.waitingRecovery')]);
    const staked = [];
    if (validator && isMicros(validator.self_bond)) staked.push(fill('account.ownValidator', { amount: amountNode(validator.self_bond) }));
    for (const position of Array.isArray(stake?.positions) ? stake.positions.slice(0, 32) : []) {
      // A position is worth its share of the validator's pool. The pool is in this proof only for
      // the account's own validator; for others the shares are shown as they are.
      const pool = position?.candidate === id && validator && isMicros(validator.pool_assets) && isMicros(validator.pool_shares) && BigInt(validator.pool_shares) > 0n && isMicros(position.shares) ? ((BigInt(position.shares) * BigInt(validator.pool_assets)) / BigInt(validator.pool_shares)).toString() : null;
      staked.push(fill(pool === null ? 'account.position' : 'account.positionValued', { shares: numberNode(position?.shares), validator: accountLink(position?.candidate), amount: pool === null ? null : amountNode(pool) }));
    }
    if (Array.isArray(stake?.exits) && stake.exits.length) staked.push([t('account.exits', { count: smallCount(stake.exits.length, 1e6) ? stake.exits.length : '?' })]);
    const policy = plain(security?.policy);
    return [stateNote(checked, failure), facts([
      ['account.frozen', frozen],
      policy ? ['account.dailyLimit', amountNode(policy.daily_limit_micros)] : null,
      policy && isMicros(policy.delay_seconds) && BigInt(policy.delay_seconds) < 18446744073709n ? ['account.delay', amountNode((BigInt(policy.delay_seconds) * 1000000n).toString())] : null,
      ['account.waiting', waiting.length ? h('ul', {}, waiting.map((nodes) => h('li', {}, nodes))) : h('span', { text: t('account.nothingWaiting') })],
      // "None" is said only of what the proof was asked about and answered.
      ['account.stake', staked.length ? h('ul', {}, staked.map((nodes) => h('li', {}, nodes))) : view.stake.known && view.validator.known ? h('span', { text: t('account.noStake') }) : missing()],
    ], { unchecked: !checked }), security ? null : h('p', {}, checked ? null : [uncheckedTag(), ' '], t('account.plain'))];
  }

  // ------------------------------------------------------------------ validators
  function viewValidators() {
    // An upgrade plan is a row of the state that a proof speaks of only when asked. The checker
    // asks with every read when the page's trust data says that the network's nodes report
    // upgrades; the row is then in the checked state and is read here. Otherwise the page says
    // that it does not read upgrade plans. It never takes silence for "no plan".
    const readsUpgrade = typeof checker.upgradeStatus === 'function';
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('validators.title') }), h('p', { text: t('validators.intro') }),
      part(t('validators.now'), async ({ reload }) => {
        let read;
        try { read = await readState(() => api.validators(), { include_pos: true }); } catch (error) { return withheld(error, reload); }
        const { checked, body, failure } = read;
        const pos = plain(checked ? checked.state.pos : body?.pos), genesis = checked ? checked.state.genesis?.genesis_time_micros : null, height = checked ? checked.height : body?.state_height;
        if (!pos) return [stateNote(checked, failure), state('empty', 'validators.noRow')];
        const mark = () => (checked ? null : [uncheckedTag(), ' ']);
        const active = (Array.isArray(pos.active) ? pos.active.slice(0, 200) : []).filter((row) => row && isMicros(row.power)).sort((a, b) => (BigInt(b.power) > BigInt(a.power) ? 1 : BigInt(b.power) < BigInt(a.power) ? -1 : 0));
        const total = active.reduce((sum, row) => sum + BigInt(row.power), 0n).toString();
        const table = active.length ? h('div', { class: checked ? 'scroll' : 'scroll unchecked' }, h('table', {}, h('caption', { text: t('validators.caption', { height: formatNumber(String(height ?? ''), words) ?? '?' }) }),
          h('thead', {}, h('tr', {}, ['validators.account', 'validators.share', 'validators.power', 'validators.key'].map((key) => h('th', { attrs: { scope: 'col' }, text: t(key) })))),
          h('tbody', {}, active.map((row) => h('tr', {}, h('th', { attrs: { scope: 'row' } }, accountLink(row.owner)), h('td', {}, mark(), t('percent', { value: formatShare(row.power, total, words) ?? '?' })), h('td', {}, numberNode(row.power)), h('td', {}, isKey(row.consensus_key) ? hexNode(row.consensus_key) : missing())))))) : state('empty', 'validators.none');
        const scheduled = Array.isArray(pos.scheduled) ? pos.scheduled.length : 0;
        let upgrade = [h('p', { text: t('validators.upgradeNotRead') })];
        if (checked && readsUpgrade && Object.hasOwn(checked.state, 'upgrade') && checked.state.upgrade !== undefined) {
          try {
            const plan = plain(checker.upgradeStatus(checked.state)?.scheduled);
            upgrade = plan ? [source('source.checked', { height: formatNumber(checked.height, words) ?? '?' }), h('p', { class: 'status', text: t('validators.upgradePlan') }), facts([
              ['validators.upgradeVersion', numberNode(plan.version)],
              ['validators.upgradeStart', isMicros(plan.activate_elapsed_micros) && isMicros(genesis) ? timeNode(timeOfMicros((BigInt(plan.activate_elapsed_micros) + BigInt(genesis)).toString())) : missing()],
              ['validators.upgradeSpec', hexNode(typeof plan.spec === 'string' && /^[0-9a-f]{64}$/.test(plan.spec) ? plan.spec : null)],
            ])] : [source('source.checked', { height: formatNumber(checked.height, words) ?? '?' }), h('p', { text: t('validators.noUpgrade') })];
          } catch { upgrade = [h('p', { text: t('validators.upgradeUnreadable') })]; }
        }
        return [stateNote(checked, failure), table, active.length ? h('p', {}, mark(), t('validators.total', { count: active.length, power: formatNumber(total, words) })) : null,
          h('section', { class: 'part' }, h('h2', { text: t('validators.changes') }), h('p', {}, mark(), scheduled ? t('validators.someChanges', { count: scheduled }) : t('validators.noChanges')), pos.safety_hold === true ? h('p', { class: 'status' }, mark(), t('validators.hold')) : null),
          h('section', { class: 'part' }, h('h2', { text: t('validators.upgrade') }), upgrade)];
      }),
      // A part of its own: it waits for nothing of the table above, and the table for nothing of it.
      part(t('validators.join'), async () => joinNodes(await joinSettings()))];
  }

  // ------------------------------------------------------------------ run a validator
  /// The text of join.json as the loader gave it (null: none was installed), kept once read. A load that failed
  /// is not kept: the next view asks again.
  let joinText;
  /// This network's facts for new validators: `join` holds what passed every test of `readJoin`, or null.
  /// `unreadable` says that a join.json was there and could not be read or did not pass, so that the page says
  /// so; it then shows the general explanation only, and nothing of the file.
  async function joinSettings() {
    if (typeof loadJoin !== 'function') return { join: null, unreadable: false };
    try {
      if (joinText === undefined) joinText = await loadJoin();
    } catch { return { join: null, unreadable: true }; }
    if (joinText === null) return { join: null, unreadable: false };
    const join = readJoin(joinText);
    return { join, unreadable: join === null };
  }
  const HOW = [['validators.how1Title', 'validators.how1'], ['validators.how2Title', null], ['validators.how3Title', 'validators.how3'], ['validators.how4Title', 'validators.how4'],
    ['validators.how5Title', 'validators.how5'], ['validators.how6Title', 'validators.how6'], ['validators.how7Title', 'validators.how7'], ['validators.how8Title', 'validators.how8']];
  /// How joining as a validator works, the steps, and with a join.json this network's script and files. All of
  /// it is the text of this page as it was installed: neither checked by the page nor the service's word about
  /// the chain, and said to be that at its end. A value of join.json is shown only after `readJoin` accepted it;
  /// the two outside links are made by dom.mjs only from addresses that pass `outsideAddress`.
  function joinNodes({ join, unreadable }) {
    const bond = join ? fill('validators.how2', { bond: amountNode(join.min_self_bond_micros) }) : t('validators.how2General');
    const wallet = join ? h('a', { outside: join.wallet_url, text: t('validators.theWallet') }) : t('validators.theWallet');
    const code = (text) => h('code', { text });
    return h('div', { class: 'join' },
      unreadable ? h('p', { class: 'status', attrs: { role: 'status' }, text: t('validators.joinUnreadable') }) : null,
      h('p', { text: t('validators.joinIntro') }),
      h('h3', { text: t('validators.howTitle') }),
      h('ol', {}, HOW.map(([title, text]) => h('li', {}, h('strong', { text: t(title) }), ' ', text ? t(text) : bond))),
      h('h3', { text: t('validators.needTitle') }),
      h('ul', {}, h('li', { text: t('validators.needMachine') }), h('li', { text: t('validators.needClock') }), h('li', { text: join ? `${t('validators.needAccount')} ${t('validators.needFaucet')}` : t('validators.needAccount') })),
      h('h3', { text: t('validators.stepsTitle') }),
      h('ol', {},
        h('li', {}, fill('validators.step1', { wallet })),
        h('li', {}, join ? [h('p', { text: t('validators.step2') }), h('pre', { class: 'commands', attrs: { 'aria-label': t('validators.commandsLabel') }, text: t('validators.commands', { script: join.script_url }) })] : t('validators.step2General')),
        h('li', { text: t('validators.step3') }), h('li', { text: t('validators.step4') })),
      h('h3', { text: t('validators.scriptTitle') }),
      h('ul', {}, ['validators.script1', 'validators.script2', 'validators.script3', 'validators.script4', 'validators.script5'].map((key) => h('li', { text: t(key) })),
        h('li', {}, fill('validators.script6', { status: code(t('validators.statusCommand')), uninstall: code(t('validators.uninstallCommand')) }))),
      join ? [h('h3', { text: t('validators.filesTitle') }), facts([
        ['validators.fileScript', h('a', { outside: join.script_url, text: join.script_url })],
        ['validators.fileChain', code(join.chain_id)],
        ['validators.fileNode', hexNode(join.files.node_sha256)],
        ['validators.fileCometbft', hexNode(join.files.cometbft_sha256)],
        ['validators.fileGenesis', hexNode(join.files.genesis_sha256)],
        [join.peers.length === 1 ? 'validators.filePeer' : 'validators.filePeers', join.peers.length === 1 ? code(join.peers[0]) : h('ul', { class: 'keys' }, join.peers.map((peer) => h('li', {}, code(peer))))],
      ])] : null,
      h('h3', { text: t('validators.careTitle') }),
      h('ul', {}, h('li', { text: t('validators.care1') }), h('li', { text: t('validators.care2') })),
      source('validators.joinInstalled'));
  }

  // ------------------------------------------------------------------ a number that may be a block or an account
  function viewFind({ number }) {
    return [h('h1', { attrs: { tabindex: '-1' }, text: t('find.title', { number }) }), h('p', { text: t('find.text') }),
      part(t('find.block', { number }), async () => { const answer = await api.block(number); return [indexSource(answer), h('p', {}, fill('find.blockFound', { link: blockLink(number), time: agoNode(timeOfMicros(answer.block?.time_micros)) }))]; }, { notFound: 'find.noBlock', notFoundValues: { number } }),
      // The account is read like on its own page: checked if the page can, otherwise the service's
      // word and marked as that; nothing of it if the service names another network.
      part(t('find.account', { number }), async ({ reload }) => {
        let read;
        try { read = await readState(() => api.account({ id: number }), { ids: [number] }); } catch (error) { return withheld(error, reload); }
        const { checked, body, failure } = read;
        if (checked) {
          const account = (Array.isArray(checked.state.accounts) ? checked.state.accounts : []).find((item) => item?.id === number) ?? null;
          if (!account && provenAbsent(checked, { id: number })) return [stateNote(checked, null), state('empty', 'find.noAccountChecked', { number, height: formatNumber(checked.height, words) ?? '?' })];
          if (!account) return withheld(new CheckFailure('silent', null, { offered: true }), reload);
          return [stateNote(checked, null), h('p', {}, isName(account.name) ? fill('find.accountNamed', { link: accountLink(number), name: nameNode(account.name) }) : fill('find.accountFound', { link: accountLink(number) }))];
        }
        const account = plain(body?.account);
        if (!account || account.id !== number) throw new ApiFailure('http', { status: 404 });
        return [stateNote(null, failure), h('p', {}, uncheckedTag(), ' ', isName(account.name) ? fill('find.accountNamed', { link: accountLink(number), name: serviceName(account.name) }) : fill('find.accountFound', { link: accountLink(number) }))];
      }, { notFound: 'find.noAccount', notFoundValues: { number } })];
  }

  // ------------------------------------------------------------------ the frame
  async function loadStatus() {
    const status = await api.status();
    lastStatus = status;
    // The checker is told which network the service names. If it is not the page's, the checker
    // checks nothing and the page shows nothing of the service's accounts and validators.
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
    // How far behind the index is, by this device's clock and the time of its newest block: not
    // by the service's own count of how far behind it is.
    const made = timeOfIso(indexer.indexed_block_time);
    if (made !== null && now() - made > 120000) notes.push(t('index.behind', { ago: agoText(made) }));
    const mismatch = trustInfo && typeof network.network_id === 'string' && network.network_id !== trustInfo.networkId;
    if (mismatch) notes.push(t('trust.mismatch'));
    $('index-note').replaceChildren(...notes.map((text) => h('p', { text })));
    $('index-note').hidden = notes.length === 0;
    $('trust-body').replaceChildren(...(trustInfo
      ? [h('p', { text: t(sameOrigin ? 'trust.textSame' : 'trust.text') }), facts([['trust.networkId', hexNode(trustInfo.networkId)], ['trust.anchor', trustInfo.anchorHeight ? [h('span', { text: `${t('trust.anchorValue', { height: formatNumber(trustInfo.anchorHeight, words) })} ` }), hexNode(trustInfo.anchorHash)] : h('span', { text: t('trust.anchorGenesis') })]])]
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
    // A manifest that could not be loaded earlier is asked for again with every view.
    if (!trustInfo) track(Promise.resolve().then(() => checker.trust()).then((info) => { if (info) { trustInfo = info; drawFrame(); } }, () => {}));
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
      trustInfo = await Promise.resolve().then(() => checker.trust()).catch(() => null);
      drawFrame();
      return render();
    },
    render, settled,
    stop() { generation += 1; for (const cleanup of cleanups.splice(0)) cleanup(); if (tick !== null) timers.clearInterval(tick); },
  };
}
