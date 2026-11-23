// Where the explorer goes: what the search box means, the address of each view, and the state of
// a paged list. Pure functions; nothing here touches the page or the network.
import { isAccountId, isHash, isHeight, isName, isCursor } from './format.mjs';

/// What a reader typed into the search box.
/// - 64 hexadecimal characters: an action.
/// - digits: a block height and an account number look the same, so the answer is 'number' and
///   the page looks both up. "0" can only be an account; a number too long for a height too.
/// - "@name", or 2 to 15 letters, digits and underscores that are not all digits: an account name.
/// Returns { kind: 'action' | 'number' | 'account' | 'empty' | 'invalid', ... }; `reason` names
/// the entry of the strings table that explains an invalid input.
export function parseSearch(input) {
  const text = typeof input === 'string' ? input.trim() : '';
  if (!text) return { kind: 'empty' };
  if (text.length > 80) return { kind: 'invalid', reason: 'search.invalid' };
  if (isHash(text)) return { kind: 'action', hash: text.toUpperCase() };
  if (/^[0-9]+$/.test(text)) {
    if (text.length > 1 && text.startsWith('0')) return { kind: 'invalid', reason: 'search.leadingZero' };
    if (isHeight(text) && isAccountId(text)) return { kind: 'number', value: text };
    if (isAccountId(text)) return { kind: 'account', id: text };
    return { kind: 'invalid', reason: 'search.tooLarge' };
  }
  const name = (text.startsWith('@') ? text.slice(1) : text).toLowerCase();
  if (isName(name)) return { kind: 'account', name };
  if (/^[0-9A-Fa-f]+$/.test(text) && text.length > 15) return { kind: 'invalid', reason: 'search.hashLength' };
  return { kind: 'invalid', reason: 'search.invalid' };
}
/// The view a search leads to, or null.
export function routeOfSearch(found) {
  if (found.kind === 'action') return { view: 'action', hash: found.hash };
  if (found.kind === 'number') return { view: 'find', number: found.value };
  if (found.kind === 'account') return found.id !== undefined ? { view: 'account', id: found.id } : { view: 'account', name: found.name };
  return null;
}

/// The view an address names. The address is the part after "#": "/", "/block/12",
/// "/action/<hash>", "/account/7", "/account/@name", "/find/12", "/validators". Each has one
/// accepted form; anything else is { view: 'unknown' }.
export function parseRoute(fragment) {
  const path = typeof fragment === 'string' ? fragment.replace(/^#/, '') : '';
  if (path === '' || path === '/') return { view: 'home' };
  if (path === '/validators') return { view: 'validators' };
  const match = /^\/(block|action|account|find)\/([0-9A-Za-z@_]{1,80})$/.exec(path);
  if (!match) return { view: 'unknown' };
  const [, kind, value] = match;
  if (kind === 'block' && isHeight(value)) return { view: 'block', height: value };
  if (kind === 'find' && isHeight(value)) return { view: 'find', number: value };
  if (kind === 'action' && isHash(value) && value === value.toUpperCase()) return { view: 'action', hash: value };
  if (kind === 'account' && isAccountId(value)) return { view: 'account', id: value };
  if (kind === 'account' && value.startsWith('@') && isName(value.slice(1))) return { view: 'account', name: value.slice(1) };
  return { view: 'unknown' };
}
/// The address of a view, as a fragment. Null when the route does not hold accepted values, so
/// that nothing from outside can become an address.
export function hrefOf(route) {
  if (route?.view === 'home') return '#/';
  if (route?.view === 'validators') return '#/validators';
  if (route?.view === 'block' && isHeight(route.height)) return `#/block/${route.height}`;
  if (route?.view === 'find' && isHeight(route.number)) return `#/find/${route.number}`;
  if (route?.view === 'action' && isHash(route.hash)) return `#/action/${route.hash.toUpperCase()}`;
  if (route?.view === 'account' && route.id !== undefined && isAccountId(route.id)) return `#/account/${route.id}`;
  if (route?.view === 'account' && route.id === undefined && isName(route.name)) return `#/account/@${route.name}`;
  return null;
}
/// Every address `hrefOf` can produce, as one pattern. The page builder refuses any other link.
export const SAFE_HREF = /^#\/(?:|validators|block\/[1-9][0-9]{0,15}|find\/[1-9][0-9]{0,15}|action\/[0-9A-F]{64}|account\/(?:0|[1-9][0-9]{0,19}|@[a-z0-9_]{2,15}))$/;

// ------------------------------------------------------------------ paging
/// A paged list keeps the cursor of every page it has shown, so that "previous" goes back without
/// asking the service to count. `cursors[i]` is the cursor that page i was asked with (null for
/// the first); `next` is the cursor of the page after the current one, if there is one.
export function newPager() { return { cursors: [null], page: 0, next: null }; }
/// The pager after the current page arrived. A `next_cursor` that does not have the form of a
/// cursor is not kept: the list then simply ends here.
export function pagerLoaded(pager, answer) {
  const more = answer?.has_more === true && isCursor(answer?.next_cursor);
  return { ...pager, next: more ? answer.next_cursor : null };
}
export const pagerCursor = (pager) => pager.cursors[pager.page];
export const canNext = (pager) => pager.next !== null;
export const canPrevious = (pager) => pager.page > 0;
export function pagerNext(pager) {
  if (!canNext(pager)) return pager;
  return { cursors: [...pager.cursors.slice(0, pager.page + 1), pager.next], page: pager.page + 1, next: null };
}
export function pagerPrevious(pager) {
  if (!canPrevious(pager)) return pager;
  return { cursors: pager.cursors, page: pager.page - 1, next: pager.cursors[pager.page] };
}
