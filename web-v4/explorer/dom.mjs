// The only code of the explorer that makes page elements. Everything goes through `h`, which
// knows a fixed set of tags and attributes, sets text as text, and takes a link only if it is one
// of the explorer's own addresses, or one of the two outside addresses a network's join.json names
// once they have passed their strict test (format.mjs, `outsideAddress`). There is no way through it
// to markup, a script, a style or any other outside address, whatever a value from the chain contains.
import { SAFE_HREF } from './route.mjs';
import { cleanText, outsideAddress } from './format.mjs';

const TAGS = new Set(['div', 'span', 'p', 'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'a', 'button', 'code', 'pre', 'strong', 'small', 'section', 'details', 'summary', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'caption', 'bdi', 'nav']);
const ATTRIBUTES = new Set(['id', 'role', 'scope', 'type', 'tabindex', 'aria-label', 'aria-live', 'aria-busy', 'aria-current', 'aria-pressed', 'aria-disabled', 'aria-describedby', 'aria-labelledby']);
const CLASS = /^[a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)*$/;

export function createDom(document) {
  /// An element. `options`: `class` (the page's own class names), `text`, `href` (an address of
  /// this explorer), `outside` (a wallet's origin or a join script, see `outsideAddress`), `attrs`
  /// (from the fixed list), `on` (event listeners). Children are elements or strings; a string
  /// becomes text.
  function h(tag, options = {}, ...children) {
    if (!TAGS.has(tag)) throw new Error('The explorer does not make this element');
    const element = document.createElement(tag);
    if (options.class !== undefined) { if (!CLASS.test(options.class)) throw new Error('Not a class name of the explorer'); element.className = options.class; }
    if (options.text !== undefined) element.textContent = String(options.text);
    if (options.href !== undefined) {
      if (tag !== 'a' || typeof options.href !== 'string' || !SAFE_HREF.test(options.href)) throw new Error('Not an address of the explorer');
      element.setAttribute('href', options.href);
    }
    if (options.outside !== undefined) {
      // The page that opens is not given this one (no opener) and is not told where the reader came from.
      if (tag !== 'a' || options.href !== undefined || outsideAddress(options.outside) === null) throw new Error('Not an outside address this page links to');
      element.setAttribute('href', options.outside);
      element.setAttribute('rel', 'noopener noreferrer');
    }
    for (const [name, value] of Object.entries(options.attrs ?? {})) {
      if (!ATTRIBUTES.has(name)) throw new Error('The explorer does not set this attribute');
      element.setAttribute(name, String(value));
    }
    for (const [type, listener] of Object.entries(options.on ?? {})) element.addEventListener(type, listener);
    for (const child of children.flat(3)) {
      if (child === null || child === undefined || child === false) continue;
      element.append(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return element;
  }
  /// Text that came from the chain or the service, shown so that it cannot pass for the page's
  /// own words: made plain (see `cleanText`), set apart in its own box, and announced as quoted
  /// text to a screen reader through `label`.
  function quoted(value, label, max = 200) {
    const { text, cut } = cleanText(value, max);
    return h('span', { class: 'chain-text' }, h('span', { class: 'sr-only', text: `${label}: ` }), h('bdi', { text: cut ? `${text}…` : text }));
  }
  /// A sentence of the strings table with elements in the places of its {placeholders}.
  function sentence(template, parts) {
    const out = [];
    for (const piece of String(template).split(/(\{[a-zA-Z]+\})/)) {
      const match = /^\{([a-zA-Z]+)\}$/.exec(piece);
      if (!match) { if (piece) out.push(piece); continue; }
      const part = parts[match[1]];
      out.push(part === undefined || part === null ? '?' : part);
    }
    return out;
  }
  return { h, quoted, sentence };
}
