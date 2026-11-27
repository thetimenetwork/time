// The hardware pages, web-v4/hardware: the drawing engine, the model of the watch, the payment of the demonstration,
// and what the pages may and may not contain. Kept here, not in that folder, so that the folder holds exactly the
// files a static server serves.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { camera, dot, circle, roundRect, band, area, prism, placed, bounds, before, drawOrder, inside, pickAt, mixer } from '../web-v4/hardware/engine.js';
import { GROUPS, MARKS, buildWatch, secondsText, clockOf, newDemo, act, mostOf, facesOf, storyOf, FEE_MS, DAILY_LIMIT_MS, STEPS_MS } from '../web-v4/hardware/watch.js';

const folder = new URL('../web-v4/hardware/', import.meta.url);
const file = (name) => readFile(new URL(name, folder), 'utf8');
const near = (a, b) => Math.abs(a - b) < 1e-9;

test('the eye: three directions at right angles, each of length one, however the watch is turned', () => {
  for (const [yaw, pitch] of [[0, 0], [-0.5, 0.95], [2, 1.42], [0.45, 2.55]]) {
    const cam = camera(yaw, pitch);
    for (const row of [cam.right, cam.up, cam.depth]) assert.ok(near(dot(row, row), 1));
    assert.ok(near(dot(cam.right, cam.up), 0) && near(dot(cam.right, cam.depth), 0) && near(dot(cam.up, cam.depth), 0));
  }
  // Looked at from the front, x goes right, y goes up and the glass faces the eye.
  assert.deepEqual(camera(0, 0), { right: [1, -0, 0], up: [0, 1, 0], depth: [-0, -0, 1] });
});

test('outlines run counter-clockwise, whatever way they were given', () => {
  assert.ok(area(circle(10)) > 0 && Math.abs(area(circle(10, 96)) - Math.PI * 100) < 0.5);
  assert.ok(near(area(roundRect(4, 2)), 8) && area(roundRect(4, 2, 0.5)) < 8);
  assert.ok(area(band([[0, 0], [5, 0], [10, 2]], 2)) > 0);
  const turned = prism({ id: 'p', outline: [[0, 0], [0, 2], [2, 2], [2, 0]], holes: [[[0.5, 0.5], [0.5, 1], [1, 1], [1, 0.5]]], from: 0, to: 1 });
  assert.ok(area(turned.outline) > 0 && area(turned.holes[0]) > 0);
  assert.deepEqual(turned.box, [0, 2, 0, 2]);
});

test('what is in front: the layers of a stack by the side the eye is on, parts with a gap by the gap, the rest by depth', () => {
  const item = (part, object = 'w', open = 0) => { const place = placed(part, {}, open), box = bounds(part, place); return { part, object, box, depth: 0 }; };
  const low = prism({ id: 'low', outline: circle(5), from: 0, to: 1, layer: 1 }), high = prism({ id: 'high', outline: circle(5), from: 0.5, to: 2, layer: 2 });
  assert.equal(before(item(low), item(high), camera(0, 0.9)), -1);   // from above, the lower layer is drawn first
  assert.equal(before(item(low), item(high), camera(0, 2.5)), 1);    // from below, the higher one
  const left = prism({ id: 'left', outline: roundRect(2, 2, 0, -5, 0), from: 0, to: 1 }), right = prism({ id: 'right', outline: roundRect(2, 2, 0, 5, 0), from: 0, to: 1 });
  assert.equal(before(item(left), item(right), camera(-1, 1.2)), -1);   // +x is towards the eye: the right one is nearer
  assert.equal(before(item(left), item(right), camera(1, 1.2)), 1);
  // Opened, a part goes where its lift takes it.
  const lifted = prism({ id: 'lifted', outline: circle(5), from: 0, to: 1, lift: [0, 0, 30] });
  assert.equal(bounds(lifted, placed(lifted, {}, 1)).min[2], 30);
  assert.equal(bounds(lifted, placed(lifted, { z: 2, turn: 1 }, 0.5)).min[2], 17);
  // Every part is drawn once, also where the pairs do not agree.
  const cam = camera(-0.5, 0.95), items = buildWatch().map((part) => { const place = placed(part, {}, 1), box = bounds(part, place); return { part, object: 'w', box, depth: dot(cam.depth, box.min.map((m, i) => (m + box.max[i]) / 2)) }; });
  const order = drawOrder(items, cam).map((it) => it.part.id);
  assert.equal(order.length, items.length); assert.equal(new Set(order).size, items.length);
  const at = (id) => order.indexOf(id);
  assert.ok(at('back') < at('battery') && at('battery') < at('board') && at('board') < at('processor') && at('processor') < at('barrel') && at('barrel') < at('coil') && at('coil') < at('display') && at('display') < at('glass'));
});

test('a point of the canvas is given back as a place on the part under it', () => {
  assert.ok(inside([1, 1], [[0, 0], [2, 0], [2, 2], [0, 2]]) && !inside([3, 1], [[0, 0], [2, 0], [2, 2], [0, 2]]));
  const square = [[100, 100], [200, 100], [200, 200], [100, 200]];
  const hits = [
    { id: 'under', group: 'a', object: 'w', walls: [], cap: { polygon: square, matrix: { a: 2, b: 0, c: 0, d: 2, e: 150, f: 150 } } },
    { id: 'over', group: 'b', object: 'w', walls: [], cap: { polygon: [[140, 140], [160, 140], [160, 160], [140, 160]], matrix: { a: 1, b: 0, c: 0, d: 1, e: 150, f: 150 } } },
    { mark: true, group: 'c', object: 'w', x: 300, y: 300, r: 19 },
  ];
  assert.equal(pickAt(hits, 150, 150).id, 'over');
  const under = pickAt(hits, 110, 190); assert.equal(under.id, 'under'); assert.deepEqual(under.on, { x: -20, y: 20 });
  assert.equal(pickAt(hits, 310, 300).group, 'c'); assert.equal(pickAt(hits, 400, 400), null);
  assert.equal(mixer([255, 255, 255], [34, 34, 34])(0), 'rgb(255,255,255)'); assert.equal(mixer([255, 255, 255], [34, 34, 34])(1), 'rgb(34,34,34)'); assert.equal(mixer([0, 0, 0], [100, 100, 100])(2), 'rgb(100,100,100)');
});

test('the watch: every part has a name of its own, and every group of the list has parts and a numbered dot', async () => {
  const parts = buildWatch();
  assert.equal(new Set(parts.map((part) => part.id)).size, parts.length);
  for (const group of GROUPS) assert.ok(parts.some((part) => part.group === group), group);
  assert.deepEqual(MARKS.map((mark) => mark.group), [...GROUPS]);
  assert.deepEqual(MARKS.map((mark) => mark.n), GROUPS.map((_, i) => i + 1));
  // The list of the page names the groups in the same order, so a number on the drawing is the number in the list.
  const page = await file('index.html');
  assert.deepEqual([...page.matchAll(/class="part-name" data-group="([a-z]+)"/g)].map((m) => m[1]), [...GROUPS]);
  // The open watch is drawn without its strap; closed, only what can be seen from outside is drawn.
  assert.ok(!buildWatch({ strap: 'none' }).some((part) => part.id.startsWith('strap')));
  assert.deepEqual(parts.filter((part) => !part.inner).map((part) => part.group).filter((g, i, all) => all.indexOf(g) === i).sort(), ['case', 'display', 'finger', 'glass', 'power']);
});

test('amounts are written in milliseconds below a second and in seconds from there', () => {
  assert.equal(secondsText(0), '0 ms'); assert.equal(secondsText(1), '1 ms'); assert.equal(secondsText(999), '999 ms');
  assert.equal(secondsText(1000), '1 s'); assert.equal(secondsText(90_000), '90 s'); assert.equal(secondsText(90_001), '90.001 s'); assert.equal(secondsText(1_500), '1.5 s');
  assert.equal(secondsText(1_234_560), '1,234.56 s');
  for (const bad of [-1, 1.5, NaN, '5', null]) assert.equal(secondsText(bad), '?');
  assert.deepEqual(clockOf(new Date(2026, 10, 27, 9, 5, 7)), { time: '09:05', date: 'Fri 27 Nov', second: 7 });
});

test('the payment of the demonstration: an amount, a touch, a review, an approval, and who carried it', () => {
  let demo = newDemo();
  assert.equal(demo.step, 'idle'); assert.equal(demo.you.online, false); assert.equal(demo.other.online, true);
  // Nothing but the next step is possible.
  for (const kind of ['plus', 'minus', 'touch', 'approve', 'settle']) assert.equal(act(demo, kind), demo, kind);
  demo = act(demo, 'give'); assert.equal(demo.step, 'amount'); assert.equal(demo.amount, 90_000);
  demo = act(demo, 'plus'); assert.equal(demo.amount, 91_000);
  demo = act(act(demo, 'unit', 0), 'minus'); assert.equal(demo.amount, 90_999);
  demo = act(act(demo, 'unit', 2), 'plus'); assert.equal(demo.amount, 150_999);
  demo = act(demo, 'turn', -3); assert.equal(demo.amount, 0);                         // never below nothing
  assert.equal(act(demo, 'touch').step, 'amount'); assert.equal(act(demo, 'touch').note, 'Set an amount first.');
  demo = act(act(demo, 'unit', 1), 'turn', 90);
  assert.equal(act(demo, 'approve'), demo);                                           // no approval before the touch and the review
  demo = act(demo, 'touch'); assert.equal(demo.step, 'review');
  assert.deepEqual(facesOf(demo).you, { screen: 'review', amount: 90_000, fee: FEE_MS, total: 90_001, to: 'anna', from: 'sam', hold: 0 });
  assert.equal(facesOf(demo, { pin: 2 }).you.screen, 'pin');
  assert.equal(act(demo, 'settle'), demo);                                            // nothing arrives that was not approved
  demo = act(demo, 'approve'); assert.equal(demo.step, 'sending');
  assert.equal(act(demo, 'cancel'), demo);                                            // final once sent
  assert.equal(act(demo, 'online', { who: 'other', on: false }), demo);
  const settled = act(demo, 'settle');
  assert.equal(settled.step, 'done'); assert.equal(settled.carrier, 'other');
  assert.equal(settled.you.balance, 842_000 - 90_000 - FEE_MS); assert.equal(settled.other.balance, 318_000 + 90_000); assert.equal(settled.you.spent, 90_000);
  assert.ok(storyOf(settled).includes("@anna's watch carried the signed payment"));
  assert.equal(facesOf(settled).other.screen, 'received');
  // With a connection of your own, your watch sends it itself.
  let own = act(newDemo(), 'online', { who: 'you', on: true });
  for (const kind of ['give', 'touch', 'approve', 'settle']) own = act(own, kind);
  assert.equal(own.carrier, 'you'); assert.ok(storyOf(own).includes('Your watch sent it itself'));
});

test('the limits of the demonstration: the day\'s limit, what the watch holds, and no payment with both sides offline', () => {
  let demo = act(act(newDemo(), 'give'), 'unit', 2);
  for (let i = 0; i < 20; i += 1) demo = act(demo, 'plus');
  assert.equal(demo.amount, DAILY_LIMIT_MS); assert.equal(mostOf(demo), DAILY_LIMIT_MS); assert.equal(demo.note, 'That is the most this watch may give today.');
  for (const kind of ['touch', 'approve', 'settle']) demo = act(demo, kind);
  assert.equal(demo.you.balance, 842_000 - DAILY_LIMIT_MS - FEE_MS);
  demo = act(demo, 'give'); assert.equal(mostOf(demo), 0); assert.equal(demo.amount, 0);   // the day's limit is used up
  // A watch that holds little gives what it holds, less the fee.
  let poor = newDemo(); poor.you.balance = 5_000; poor = act(poor, 'give');
  assert.equal(poor.amount, 4_999); assert.equal(act(poor, 'plus').note, 'That is all the watch holds, less the fee.');
  // Both offline.
  let dark = act(act(newDemo(), 'online', { who: 'other', on: false }), 'give');
  dark = act(dark, 'touch'); assert.equal(dark.step, 'blocked'); assert.equal(facesOf(dark).you.screen, 'notice');
  assert.ok(storyOf(dark).includes('Both watches are offline')); assert.equal(act(dark, 'approve'), dark);
  assert.equal(act(dark, 'online', { who: 'you', on: true }).step, 'amount');
  assert.deepEqual([...STEPS_MS], [1, 1000, 60_000]);
});

test('the pages: only their own files, no code or style in the markup, nothing fetched and nothing stored', async () => {
  assert.deepEqual((await readdir(folder)).sort(), ['404.html', 'app.js', 'engine.js', 'icon.svg', 'index.html', 'styles.css', 'watch.js']);
  for (const name of ['index.html', '404.html']) {
    const page = await file(name);
    assert.ok(!/<style|style=|\son[a-z]+=|<script(?![^>]*\ssrc=)|javascript:/i.test(page), name);
    for (const [, address] of page.matchAll(/(?:src|href)="([^"]+)"/g)) assert.ok(/^(?:#[a-z-]+|\/?[a-z0-9.-]*|https:\/\/thetimenetwork\.org|https:\/\/github\.com\/thetimenetwork\/time)$/.test(address), address);
    assert.ok(page.includes('<strong>Design draft 0.1.</strong> No watch has been built or tested. Nothing here is for sale.'), name);
  }
  const page = await file('index.html');
  for (const id of ['hero-scene', 'demo-scene', 'inside-scene', 'demo-story', 'demo-give', 'demo-touch', 'demo-hold', 'demo-pin', 'open-toggle', 'parts']) assert.ok(page.includes(`id="${id}"`), id);
  assert.ok(page.includes('No company named on this page is a partner of this project or has reviewed this design.'));
  assert.ok(page.includes('Nothing is sent anywhere and no key is used.'));
  for (const name of ['app.js', 'engine.js', 'watch.js']) {
    const source = await file(name);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|fetch\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB|document\.cookie|cssText|setAttribute\('style'/.test(source), name);
    for (const [, from] of source.matchAll(/from '([^']+)'/g)) assert.ok(['./engine.js', './watch.js'].includes(from), from);
  }
});

test('the style sheet starts with the tokens of every Time page and loads nothing', async () => {
  const cut = (css) => { const lines = css.split(/\r?\n/), from = lines.findIndex((l) => l.startsWith(':root {')), to = lines.findIndex((l) => l.startsWith('@media (max-width: 22.5rem)')); assert.ok(from >= 0 && to > from); return lines.slice(from, to + 1).join('\n'); };
  const css = await file('styles.css');
  assert.equal(cut(css), cut(await readFile(new URL('../web-v4/site/styles.css', import.meta.url), 'utf8')));
  assert.ok(!/url\(|@import|expression\(|http/i.test(css));
  // The drawings take their two colours from these tokens (app.js, readPalette).
  for (const token of ['--page: #ffffff', '--ink: #222222', '--page: #121212', '--ink: #ededed']) assert.ok(css.includes(token), token);
});
