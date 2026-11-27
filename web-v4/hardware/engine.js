// A small drawing engine for the hardware pages: solid shapes drawn as fine lines on a canvas, with no library.
//
// Everything is a prism: a flat outline (with holes, if any) pushed along an axis. A watch is a stack of them. The
// view is parallel (no perspective), so a flat face of the model stays a parallelogram on the screen and a picture
// drawn on it (a watch face, the tracks of a board) needs one plain 2D transform.
//
// What is in front of what is decided without a depth buffer:
// - parts of one stack carry a `layer`; between two layers the order follows from which side the eye is on;
// - two parts with a gap between them along x, y or z are ordered by the side of that gap the eye is on;
// - anything else falls back to the depth of the middle of each part.
// Within a prism: the walls seen through a hole, then the other walls from far to near, then the cap that faces the eye.
//
// Units: millimetres in the model, CSS pixels on the screen. The functions above `render` run under Node too
// (client-v4/hardware-page.test.mjs).

export const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const TAU = Math.PI * 2;

/// The eye: `yaw` turns the model about its own z axis, `pitch` tips it (0 looks straight at the top, a quarter turn
/// looks at the side, a half turn at the bottom). Three rows: what goes right, up and towards the eye on the screen.
export function camera(yaw, pitch) {
  const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
  return { right: [cy, -sy, 0], up: [sy * cp, cy * cp, sp], depth: [-sy * sp, -cy * sp, cp] };
}

/// Outlines, counter-clockwise, as [u, v] points.
export function circle(r, n = 48, cx = 0, cy = 0) {
  return Array.from({ length: n }, (_, i) => [cx + r * Math.cos(TAU * i / n), cy + r * Math.sin(TAU * i / n)]);
}
export function roundRect(w, h, r = 0, cx = 0, cy = 0, n = 5) {
  const rr = Math.min(r, w / 2, h / 2), out = [];
  if (rr <= 0) return [[cx - w / 2, cy - h / 2], [cx + w / 2, cy - h / 2], [cx + w / 2, cy + h / 2], [cx - w / 2, cy + h / 2]];
  const corners = [[cx + w / 2 - rr, cy - h / 2 + rr, -Math.PI / 2], [cx + w / 2 - rr, cy + h / 2 - rr, 0], [cx - w / 2 + rr, cy + h / 2 - rr, Math.PI / 2], [cx - w / 2 + rr, cy - h / 2 + rr, Math.PI]];
  for (const [x, y, start] of corners) for (let i = 0; i <= n; i += 1) { const a = start + (Math.PI / 2) * i / n; out.push([x + rr * Math.cos(a), y + rr * Math.sin(a)]); }
  return out;
}
/// A band of thickness `t` along a centre line of [u, v] points: the outline of a strap seen from its edge.
export function band(line, t) {
  const side = (sign) => line.map((p, i) => {
    const a = line[Math.max(0, i - 1)], b = line[Math.min(line.length - 1, i + 1)], du = b[0] - a[0], dv = b[1] - a[1], len = Math.hypot(du, dv) || 1;
    return [p[0] + sign * (-dv / len) * t / 2, p[1] + sign * (du / len) * t / 2];
  });
  const out = [...side(-1), ...side(1).reverse()];
  return area(out) < 0 ? out.reverse() : out;
}
export function area(points) {
  let sum = 0;
  for (let i = 0; i < points.length; i += 1) { const a = points[i], b = points[(i + 1) % points.length]; sum += a[0] * b[1] - b[0] * a[1]; }
  return sum / 2;
}

const FRAMES = { z: { u: [1, 0, 0], v: [0, 1, 0], w: [0, 0, 1] }, x: { u: [0, 1, 0], v: [0, 0, 1], w: [1, 0, 0] } };

/// One part. `axis`: 'z' (outline in x and y, pushed along z) or 'x' (outline in y and z, pushed along x). `from`, `to`:
/// where it starts and ends along that axis. `lift`: where it goes when the watch is opened. `tone`: 0 is the page, 1 is
/// ink. `smooth`: a round wall, drawn without the lines between its flat pieces. `inner`: hidden while the watch is
/// closed. `top`, `bottom`: a function that draws on that cap (see `pen` below), in millimetres times `unit`.
export function prism(spec) {
  const outline = area(spec.outline) < 0 ? [...spec.outline].reverse() : spec.outline;
  const holes = (spec.holes ?? []).map((hole) => (area(hole) < 0 ? [...hole].reverse() : hole));
  const us = outline.map((p) => p[0]), vs = outline.map((p) => p[1]);
  return {
    id: spec.id, group: spec.group ?? spec.id, axis: spec.axis ?? 'z', outline, holes, from: spec.from, to: spec.to,
    at: spec.at ?? [0, 0, 0], lift: spec.lift ?? [0, 0, 0], tone: spec.tone ?? 0.05, alpha: spec.alpha ?? 1, smooth: spec.smooth === true,
    layer: spec.layer ?? null, inner: spec.inner === true, top: spec.top ?? null, bottom: spec.bottom ?? null, unit: spec.unit ?? 1,
    box: [Math.min(...us), Math.max(...us), Math.min(...vs), Math.max(...vs)],
  };
}

/// Where a part is: its three axes and its origin in the scene, for an object standing at `pose` ({ x, y, z, turn })
/// and opened by `open` (0 closed, 1 fully apart).
export function placed(part, pose = {}, open = 0) {
  const turn = pose.turn ?? 0, c = Math.cos(turn), s = Math.sin(turn), spin = (p) => [p[0] * c - p[1] * s, p[0] * s + p[1] * c, p[2]];
  const frame = FRAMES[part.axis], local = [part.at[0] + part.lift[0] * open, part.at[1] + part.lift[1] * open, part.at[2] + part.lift[2] * open], o = spin(local);
  return { u: spin(frame.u), v: spin(frame.v), w: spin(frame.w), o: [o[0] + (pose.x ?? 0), o[1] + (pose.y ?? 0), o[2] + (pose.z ?? 0)] };
}
/// The box, along x, y and z of the scene, that holds a placed part.
export function bounds(part, place) {
  const min = [Infinity, Infinity, Infinity], max = [-Infinity, -Infinity, -Infinity], [u0, u1, v0, v1] = part.box;
  for (const u of [u0, u1]) for (const v of [v0, v1]) for (const w of [part.from, part.to]) for (let k = 0; k < 3; k += 1) {
    const value = place.o[k] + u * place.u[k] + v * place.v[k] + w * place.w[k];
    if (value < min[k]) min[k] = value; if (value > max[k]) max[k] = value;
  }
  return { min, max };
}

const GAP = 0.02, EDGE_ON = 0.02;
/// Which of two placed parts is drawn first: -1 for `a`, 1 for `b`, 0 when nothing says. Each is { part, object, box,
/// depth } with `box` from `bounds` and `depth` the depth of its middle.
export function before(a, b, cam) {
  if (a.object === b.object && a.part.layer !== null && b.part.layer !== null && a.part.layer !== b.part.layer && Math.abs(cam.depth[2]) > EDGE_ON) {
    return (a.part.layer < b.part.layer) === (cam.depth[2] > 0) ? -1 : 1;
  }
  let sure = 0, answer = 0;
  for (let k = 0; k < 3; k += 1) {
    const d = cam.depth[k];
    if (Math.abs(d) <= Math.max(EDGE_ON, sure)) continue;
    if (a.box.max[k] <= b.box.min[k] + GAP) { sure = Math.abs(d); answer = d > 0 ? -1 : 1; }
    else if (b.box.max[k] <= a.box.min[k] + GAP) { sure = Math.abs(d); answer = d > 0 ? 1 : -1; }
  }
  if (answer) return answer;
  return a.depth < b.depth ? -1 : a.depth > b.depth ? 1 : 0;
}
/// The parts from the farthest to the nearest. Where the pairs disagree in a circle, the farthest of those left goes first.
export function drawOrder(items, cam) {
  const n = items.length, waits = new Array(n).fill(0), after = items.map(() => []);
  for (let i = 0; i < n; i += 1) for (let j = i + 1; j < n; j += 1) {
    const first = before(items[i], items[j], cam);
    if (first < 0) { after[i].push(j); waits[j] += 1; } else if (first > 0) { after[j].push(i); waits[i] += 1; }
  }
  const left = new Set(items.keys()), out = [];
  while (left.size) {
    let pick = -1, free = false;
    for (const i of left) {
      const isFree = waits[i] === 0;
      if (pick < 0 || (isFree && !free) || (isFree === free && items[i].depth < items[pick].depth)) { pick = i; free = isFree; }
    }
    left.delete(pick); out.push(items[pick]);
    for (const j of after[pick]) waits[j] -= 1;
  }
  return out;
}

export function inside(point, polygon) {
  let hit = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i, i += 1) {
    const a = polygon[i], b = polygon[j];
    if ((a[1] > point[1]) !== (b[1] > point[1]) && point[0] < (b[0] - a[0]) * (point[1] - a[1]) / (b[1] - a[1]) + a[0]) hit = !hit;
  }
  return hit;
}
/// What is under a point of the canvas, from the list `render` returned: the nearest mark or part, with the place on
/// its top cap when the point is on it ({ x, y } in the cap's own units, y down).
export function pickAt(hits, x, y) {
  for (let i = hits.length - 1; i >= 0; i -= 1) {
    const hit = hits[i];
    if (hit.mark) { if (Math.hypot(x - hit.x, y - hit.y) <= hit.r) return hit; continue; }
    if (hit.cap && inside([x, y], hit.cap.polygon)) {
      const { a, b, c, d, e, f } = hit.cap.matrix, det = a * d - b * c;
      if (Math.abs(det) > 1e-9) return { ...hit, on: { x: (d * (x - e) - c * (y - f)) / det, y: (a * (y - f) - b * (x - e)) / det } };
    }
    if (hit.walls.some((polygon) => inside([x, y], polygon)) || (hit.cap && inside([x, y], hit.cap.polygon))) return { ...hit, on: null };
  }
  return null;
}

/// A colour between the page (0) and ink (1). `page` and `ink` are [r, g, b].
export function mixer(page, ink) {
  return (k) => { const t = Math.max(0, Math.min(1, k)); return `rgb(${page.map((p, i) => Math.round(p + (ink[i] - p) * t)).join(',')})`; };
}

const LIGHT = (() => { const v = [-0.42, 0.55, 0.72], len = Math.hypot(...v); return v.map((x) => x / len); })();

/// Draws a scene and returns what was drawn where, for `pickAt`.
/// `ctx`: a 2D context whose transform is the device's pixel ratio. `view`: { width, height, cx, cy, zoom, yaw, pitch }.
/// `objects`: [{ key, parts, pose, open, state }]; `state` reaches the caps' drawing functions. `palette`: { page, ink }
/// as [r, g, b]. `selected`: a group drawn in ink. `marks`: [{ n, group, object, c: [x, y, z], r, side, lift, dx, dy }]: numbered
/// dots, each `r` to the left (side -1) or the right (1) of the point `c` as the screen has it.
export function render(ctx, { view, objects, palette, ratio = 1, selected = null, marks = [], font = 'system-ui, sans-serif' }) {
  const cam = camera(view.yaw, view.pitch), mix = mixer(palette.page, palette.ink), hits = [];
  const toView = (p) => [dot(cam.right, p), dot(cam.up, p), dot(cam.depth, p)];
  const screen = (p) => [view.cx + view.zoom * p[0], view.cy - view.zoom * p[1]];
  const base = () => ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  base(); ctx.clearRect(0, 0, view.width, view.height); ctx.lineJoin = 'round'; ctx.lineCap = 'round';

  const items = [];
  for (const object of objects) for (const part of object.parts) {
    if (part.inner && (object.open ?? 0) < 0.02) continue;
    const place = placed(part, object.pose, object.open ?? 0), box = bounds(part, place);
    const U = toView(place.u), V = toView(place.v), W = toView(place.w), O = toView(place.o);
    const mid = [(box.min[0] + box.max[0]) / 2, (box.min[1] + box.max[1]) / 2, (box.min[2] + box.max[2]) / 2];
    items.push({ part, object, box, depth: dot(cam.depth, mid), U, V, W, O });
  }

  for (const item of drawOrder(items, cam)) {
    // With a group chosen, its parts are drawn in ink and the others step back.
    const { part, object, U, V, W, O } = item, chosen = selected !== null && part.group === selected, aside = selected !== null && !chosen;
    const tone = chosen ? Math.max(part.tone, 0.84) : aside ? part.tone * 0.45 : part.tone, dark = tone > 0.5, line = dark ? mix(0.3) : mix(aside ? 0.4 : 1);
    const at = (p, w) => screen([O[0] + p[0] * U[0] + p[1] * V[0] + w * W[0], O[1] + p[0] * U[1] + p[1] * V[1] + w * W[1]]);
    const shade = (n) => mix(tone + (dark ? -0.16 : 0.13) * (1 - Math.max(0, dot(n, LIGHT))));
    const topSeen = W[2] > 1e-4, bottomSeen = W[2] < -1e-4, near = topSeen ? part.to : part.from, far = topSeen ? part.from : part.to;
    const record = { id: part.id, group: part.group, object: object.key, walls: [], cap: null };

    const walls = [];
    const ring = (points, sign, hole) => {
      const n = points.length, seen = new Array(n), normals = new Array(n);
      for (let i = 0; i < n; i += 1) {
        const a = points[i], b = points[(i + 1) % n], du = b[0] - a[0], dv = b[1] - a[1], len = Math.hypot(du, dv) || 1, nu = sign * dv / len, nv = -sign * du / len;
        normals[i] = [nu * U[0] + nv * V[0], nu * U[1] + nv * V[1], nu * U[2] + nv * V[2], nu, nv];
        seen[i] = normals[i][2] > 1e-4;
        if (seen[i]) { const m = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2]; walls.push({ hole, i, a, b, n: normals[i], depth: O[2] + m[0] * U[2] + m[1] * V[2] }); }
      }
      return { points, seen, normals, n };
    };
    const rings = [ring(part.outline, 1, false), ...part.holes.map((hole) => ring(hole, -1, true))];
    walls.sort((p, q) => (p.hole === q.hole ? p.depth - q.depth : p.hole ? -1 : 1));

    ctx.globalAlpha = part.alpha;
    for (const wall of walls) {
      const quad = [at(wall.a, part.from), at(wall.b, part.from), at(wall.b, part.to), at(wall.a, part.to)];
      ctx.beginPath(); quad.forEach((p, i) => (i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]))); ctx.closePath();
      ctx.fillStyle = ctx.strokeStyle = shade(wall.n); ctx.lineWidth = 0.75; ctx.fill(); ctx.stroke();
      record.walls.push(quad);
    }
    ctx.globalAlpha = 1;
    // The lines of the walls: the rim away from the eye, the outline of the shape, and its real corners.
    ctx.strokeStyle = line; ctx.lineWidth = 1.2; ctx.beginPath();
    for (const r of rings) for (let i = 0; i < r.n; i += 1) {
      const prev = (i + r.n - 1) % r.n, a = r.points[i], b = r.points[(i + 1) % r.n];
      if (r.seen[i]) { const p = at(a, far), q = at(b, far); ctx.moveTo(p[0], p[1]); ctx.lineTo(q[0], q[1]); if (!topSeen && !bottomSeen) { const s = at(a, near), t = at(b, near); ctx.moveTo(s[0], s[1]); ctx.lineTo(t[0], t[1]); } }
      const corner = r.normals[i][3] * r.normals[prev][3] + r.normals[i][4] * r.normals[prev][4] < 0.8;
      if (r.seen[i] !== r.seen[prev] || (corner && !part.smooth && (r.seen[i] || r.seen[prev]))) { const p = at(a, part.from), q = at(a, part.to); ctx.moveTo(p[0], p[1]); ctx.lineTo(q[0], q[1]); }
    }
    ctx.stroke();

    if (topSeen || bottomSeen) {
      const normal = topSeen ? W : [-W[0], -W[1], -W[2]];
      ctx.beginPath();
      for (const r of rings) { r.points.forEach((p, i) => { const s = at(p, near); if (i) ctx.lineTo(s[0], s[1]); else ctx.moveTo(s[0], s[1]); }); ctx.closePath(); }
      ctx.globalAlpha = part.alpha; ctx.fillStyle = shade(normal); ctx.fill('evenodd'); ctx.globalAlpha = 1;
      ctx.strokeStyle = line; ctx.lineWidth = 1.2; ctx.stroke();
      // The cap's own picture. Its units: x along u, y down the screen when the watch is looked at from that side.
      const k = part.unit, flip = topSeen ? -1 : 1, o = screen([O[0] + near * W[0], O[1] + near * W[1]]);
      const matrix = { a: view.zoom * U[0] * k, b: -view.zoom * U[1] * k, c: flip * view.zoom * V[0] * k, d: -flip * view.zoom * V[1] * k, e: o[0], f: o[1] };
      record.cap = { top: topSeen, polygon: part.outline.map((p) => at(p, near)), matrix };
      const draw = topSeen ? part.top : part.bottom;
      if (draw) {
        const on = () => ctx.setTransform(ratio * matrix.a, ratio * matrix.b, ratio * matrix.c, ratio * matrix.d, ratio * matrix.e, ratio * matrix.f);
        ctx.save();
        draw(pen(ctx, { on, base, mix, dark, font }), object.state ?? {}, { chosen, zoom: view.zoom * k });
        ctx.restore(); base(); ctx.globalAlpha = 1; ctx.setLineDash([]);
      }
    }
    hits.push(record);
  }

  // The numbered dots, each on a short line from its part.
  for (const mark of marks) {
    const object = objects.find((o) => o.key === mark.object) ?? objects[0], open = object.open ?? 0, turn = object.pose?.turn ?? 0, c = Math.cos(turn), s = Math.sin(turn);
    const local = [mark.c[0] + (mark.lift?.[0] ?? 0) * open, mark.c[1] + (mark.lift?.[1] ?? 0) * open, mark.c[2] + (mark.lift?.[2] ?? 0) * open], out = (mark.r ?? 0) * (mark.side ?? 1);
    const world = [local[0] * c - local[1] * s + (object.pose?.x ?? 0) + out * cam.right[0], local[0] * s + local[1] * c + (object.pose?.y ?? 0) + out * cam.right[1], local[2] + (object.pose?.z ?? 0)];
    const from = screen(toView(world)), to = [from[0] + mark.dx, from[1] + mark.dy], chosen = selected === mark.group, r = 13;
    ctx.strokeStyle = mix(1); ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(from[0], from[1]); ctx.lineTo(to[0], to[1]); ctx.stroke();
    ctx.beginPath(); ctx.arc(from[0], from[1], 2.2, 0, TAU); ctx.fillStyle = mix(1); ctx.fill();
    ctx.beginPath(); ctx.arc(to[0], to[1], r, 0, TAU); ctx.fillStyle = chosen ? mix(1) : mix(0); ctx.fill(); ctx.lineWidth = 1.5; ctx.stroke();
    ctx.fillStyle = chosen ? mix(0) : mix(1); ctx.font = `700 13px ${font}`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(String(mark.n), to[0], to[1] + 0.5);
    hits.push({ mark: true, group: mark.group, object: object.key, x: to[0], y: to[1], r: r + 6 });
  }
  return hits;
}

/// What a cap's drawing function draws with. Shapes are given in the cap's units; lines keep their width on the screen.
function pen(ctx, { on, base, mix, dark, font }) {
  const ink = (tone) => mix(dark ? 1 - tone : tone);
  const p = {
    begin() { on(); ctx.beginPath(); return p; },
    move(x, y) { ctx.moveTo(x, y); return p; },
    line(x, y) { ctx.lineTo(x, y); return p; },
    close() { ctx.closePath(); return p; },
    arc(x, y, r, from = 0, to = TAU, back = false) { ctx.arc(x, y, r, from, to, back); return p; },
    circle(x, y, r) { ctx.moveTo(x + r, y); ctx.arc(x, y, r, 0, TAU); return p; },
    rect(x, y, w, h, r = 0) { if (r > 0 && ctx.roundRect) ctx.roundRect(x, y, w, h, r); else ctx.rect(x, y, w, h); return p; },
    stroke(width = 1.2, tone = 1, dash = null) { base(); ctx.setLineDash(dash ?? []); ctx.lineWidth = width; ctx.strokeStyle = ink(tone); ctx.stroke(); ctx.setLineDash([]); on(); return p; },
    fill(tone = 1, alpha = 1, rule = 'nonzero') { ctx.globalAlpha = alpha; ctx.fillStyle = ink(tone); ctx.fill(rule); ctx.globalAlpha = 1; return p; },
    text(words, x, y, size, { weight = 600, align = 'center', tone = 1, mono = false } = {}) {
      on(); ctx.font = `${weight} ${size}px ${mono ? 'ui-monospace, Consolas, monospace' : font}`; ctx.textAlign = align; ctx.textBaseline = 'middle'; ctx.fillStyle = ink(tone); ctx.fillText(words, x, y); return p;
    },
    width(words, size, weight = 600) { ctx.font = `${weight} ${size}px ${font}`; return ctx.measureText(words).width; },
  };
  return p;
}
