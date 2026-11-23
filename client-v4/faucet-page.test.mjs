// The faucet page (web-v4/faucet/app.js): an account named in the address fills the field, by the page's own rule.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { accountFromAddress } from '../web-v4/faucet/app.js';

test('the faucet page takes ?account= into its field only if it is an account by the page\'s rule', async () => {
  assert.equal(accountFromAddress('?account=alice'), 'alice');
  assert.equal(accountFromAddress('?account=%40Alice_2'), '@alice_2');
  assert.equal(accountFromAddress('?account=42&x=1'), '42');
  // Trimmed and lower-cased, as the page treats what is typed into the field.
  assert.equal(accountFromAddress('?account=%20bob%20'), 'bob'); assert.equal(accountFromAddress('?account=carol%0A'), 'carol');
  for (const bad of ['', '?', '?name=alice', '?account=', '?account=a%20b', '?account=a%0Ab', '?account=%3Cscript%3E', '?account=' + 'a'.repeat(21), '?account=al-ice', '?account=%E2%80%AEx']) assert.equal(accountFromAddress(bad), '', bad);
  // The DOM part puts it into the field as a value, never as markup.
  const script = await readFile(new URL('../web-v4/faucet/app.js', import.meta.url), 'utf8');
  assert(script.includes("const named = accountFromAddress(window.location.search);\n  if (named) $('account').value = named;"));
});
