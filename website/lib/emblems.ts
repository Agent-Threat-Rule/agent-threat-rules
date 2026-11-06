/* Line emblems in a Greek classical idiom, drawn on a 64x64 grid.
 * Each emblem is plain geometry: strokes in the current text colour, plus an
 * optional "accent" set drawn in the alert colour (the poisoned grain, the
 * hidden line in the scroll). Kept as data so React and build scripts share it. */

export type Shape =
  | { d: string; fill?: boolean }
  | { c: [number, number, number]; fill?: boolean };

export interface Emblem {
  base: ReadonlyArray<Shape>;
  accent?: ReadonlyArray<Shape>;
}

const p = (d: string, fill = false): Shape => ({ d, fill });
const o = (cx: number, cy: number, r: number, fill = false): Shape => ({ c: [cx, cy, r], fill });
const r2 = (n: number) => Math.round(n * 100) / 100;

/** Almond-shaped leaf or grain at (x, y), pointing along angle (radians). */
function leaf(x: number, y: number, angle: number, len: number, width: number): string {
  const tx = x + Math.cos(angle) * len;
  const ty = y + Math.sin(angle) * len;
  const mx = (x + tx) / 2;
  const my = (y + ty) / 2;
  const nx = -Math.sin(angle) * width;
  const ny = Math.cos(angle) * width;
  return `M${r2(x)} ${r2(y)} Q${r2(mx + nx)} ${r2(my + ny)} ${r2(tx)} ${r2(ty)} Q${r2(mx - nx)} ${r2(my - ny)} ${r2(x)} ${r2(y)}Z`;
}

/** Point and tangent angle on a cubic Bezier. */
function cubic(t: number, a: number[], b: number[], c: number[], d: number[]): [number, number, number] {
  const u = 1 - t;
  const x = u * u * u * a[0] + 3 * u * u * t * b[0] + 3 * u * t * t * c[0] + t * t * t * d[0];
  const y = u * u * u * a[1] + 3 * u * u * t * b[1] + 3 * u * t * t * c[1] + t * t * t * d[1];
  const dx = 3 * u * u * (b[0] - a[0]) + 6 * u * t * (c[0] - b[0]) + 3 * t * t * (d[0] - c[0]);
  const dy = 3 * u * u * (b[1] - a[1]) + 6 * u * t * (c[1] - b[1]) + 3 * t * t * (d[1] - c[1]);
  return [x, y, Math.atan2(dy, dx)];
}

function laurelBranch(mirror: boolean): Shape[] {
  const f = (x: number) => (mirror ? 64 - x : x);
  const a = [f(31), 56];
  const b = [f(14), 50];
  const c = [f(7), 34];
  const d = [f(15), 13];
  const out: Shape[] = [p(`M${a[0]} ${a[1]} C${b[0]} ${b[1]} ${c[0]} ${c[1]} ${d[0]} ${d[1]}`)];
  for (let i = 1; i <= 7; i++) {
    const [x, y, ang] = cubic(i / 8, a, b, c, d);
    const side = mirror ? -1 : 1;
    out.push(p(leaf(x, y, ang - side * 0.75, 7, 2.2)));
    out.push(p(leaf(x, y, ang + side * 0.75, 6, 2)));
  }
  out.push(p(leaf(d[0], d[1], cubic(1, a, b, c, d)[2], 6, 2)));
  return out;
}

function wheatEar(): { base: Shape[]; accent: Shape[] } {
  const base: Shape[] = [p("M32 58 V10")];
  const accent: Shape[] = [];
  for (let i = 0; i < 6; i++) {
    const y = 46 - i * 6;
    const left = leaf(32, y, -Math.PI / 2 - 0.55, 9, 2.6);
    const right = leaf(32, y, -Math.PI / 2 + 0.55, 9, 2.6);
    base.push(p(left));
    (i === 3 ? accent : base).push(p(right, i === 3));
  }
  base.push(p(leaf(32, 14, -Math.PI / 2, 8, 2.4)));
  return { base, accent };
}

function wheelSpokes(): Shape[] {
  const out: Shape[] = [];
  for (let i = 0; i < 8; i++) {
    const a = (i * Math.PI) / 4;
    out.push(p(`M${r2(34 + Math.cos(a) * 4.5)} ${r2(32 + Math.sin(a) * 4.5)} L${r2(34 + Math.cos(a) * 17)} ${r2(32 + Math.sin(a) * 17)}`));
  }
  return out;
}

function beadRing(cx: number, cy: number, r: number, n: number, size: number): Shape[] {
  return Array.from({ length: n }, (_, i) => {
    const a = (i / n) * Math.PI * 2;
    return o(r2(cx + Math.cos(a) * r), r2(cy + Math.sin(a) * r), size, true);
  });
}

const wheat = wheatEar();

export const EMBLEMS = {
  /** A rule written in stone: pediment, inscribed tablet, base. */
  stele: {
    base: [
      p("M18 19 L32 9 L46 19 Z"),
      o(32, 15.2, 1.6),
      p("M20 19 V54 H44 V19"),
      p("M16 54 H48 V58 H16 Z"),
      p("M24 26 H40 M24 31 H40 M24 36 H37 M24 41 H40 M24 46 H34"),
    ],
  },
  /** Weighing what must be caught against what must be left alone. */
  scales: {
    base: [
      o(32, 10, 2),
      p("M32 12 V53 M24 53 H40 M21 57 H43"),
      p("M13 19 Q32 15 51 19"),
      p("M13 19 L8 35 M13 19 L18 35 M51 19 L46 35 M51 19 L56 35"),
      p("M7 35 H19 Q13 42 7 35 Z M45 35 H57 Q51 42 45 35 Z"),
    ],
  },
  /** A square labyrinth: the path from a request to the tests that fit it. */
  labyrinth: {
    base: [p("M10 54 V10 H54 V54 H16 V16 H48 V48 H22 V22 H42 V42 H28 V28 H36 V36 H32")],
    accent: [o(32, 32, 1.5, true)],
  },
  /** A wreath for what has shipped. */
  laurel: {
    base: [...laurelBranch(false), ...laurelBranch(true), p("M27.5 53 Q32 59 36.5 53 M29.5 58.5 L27 62 M34.5 58.5 L37 62")],
  },
  /** A torch: the incident that lights the next rule. */
  torch: {
    base: [p("M26 30 H38 M28 30 L31 57 H33 L36 30 M28.6 35 H35.4 M29.2 40 H34.8")],
    accent: [p("M32 27 C25 22 29 15 32 7 C34 14 39 19 32 27 Z"), p("M32 23.5 C30 21 30.6 18 32 14.5 C33.4 18 34 21 32 23.5 Z")],
  },
  /** An Ionic column: the standard and the people who hold it up. */
  column: {
    base: [
      p("M20 15 H44 V18 H20 Z"),
      p("M21 18 C17 18 16 23 19.5 23.5 C22 23.8 22.6 21 20.8 20.6"),
      p("M43 18 C47 18 48 23 44.5 23.5 C42 23.8 41.4 21 43.2 20.6"),
      p("M23 21 H41"),
      p("M25 22 V50 M39 22 V50 M29.5 23 V49 M34.5 23 V49"),
      p("M22 50 H42 V53 H22 Z M18 53 H46 V57 H18 Z"),
    ],
  },
  /** A round shield with a bead rim. */
  aspis: {
    base: [o(32, 32, 24), o(32, 32, 20), ...beadRing(32, 32, 22, 28, 0.55), o(32, 32, 8), o(32, 32, 2.2, true)],
  },
  /** Instructions hidden among the lines of a scroll. */
  scroll: {
    base: [
      p("M19 15 H45 V49 H19 Z"),
      p("M15 12 H49 V15 H15 Z M15 49 H49 V52 H15 Z"),
      p("M23 21 H41 M23 26 H41 M23 36 H41 M23 41 H35"),
    ],
    accent: [p("M23 31 H38")],
  },
  /** A key: whoever holds it gets in. */
  key: {
    base: [o(18, 32, 8), o(18, 32, 3.5), p("M26 32 H54 M54 32 V41 H50 V36 M45 32 V39 H41 V35")],
  },
  /** An amphora losing what it carries. */
  amphora: {
    base: [
      p("M27 12 H37 M28 12 V18 C28 21 20 24 20 34 C20 44 26 49 29 51 L28 56 H36 L35 51 C38 49 44 44 44 34 C44 24 36 21 36 18 V12"),
      p("M28 18 C22 18 21 23 23.5 26.5 M36 18 C42 18 43 23 40.5 26.5"),
      p("M21.3 30 H42.7 M20.6 38 H43.4"),
    ],
    accent: [p("M47 30 C45.6 32 45.6 33.4 47 33.4 C48.4 33.4 48.4 32 47 30 Z"), p("M49.5 38 C48.3 39.7 48.3 40.9 49.5 40.9 C50.7 40.9 50.7 39.7 49.5 38 Z")],
  },
  /** A lyre: the song that talks the sailor off course. */
  lyre: {
    base: [
      p("M24 49 C15 42 13 31 17 22 C19 17.5 16.5 13.5 13 14.5"),
      p("M40 49 C49 42 51 31 47 22 C45 17.5 47.5 13.5 51 14.5"),
      p("M16.5 24 H47.5"),
      p("M21 47 H43 C43 56 21 56 21 47 Z"),
      p("M27.5 24 V47 M30.5 24 V47 M33.5 24 V47 M36.5 24 V47"),
    ],
  },
  /** A cup with something dropped in it. */
  kylix: {
    base: [
      p("M13 27 H51 C49 35 41 39 32 39 C23 39 15 35 13 27 Z"),
      p("M13 29 C8 29 8 23 13.5 23 M51 29 C56 29 56 23 50.5 23"),
      p("M32 39 V48 M24 52 C26 48 38 48 40 52 Z"),
    ],
    accent: [p("M32 10 C29 14.5 29 18 32 18 C35 18 35 14.5 32 10 Z")],
  },
  /** Temple steps, taken one at a time. */
  steps: {
    base: [p("M8 56 H56 M8 56 V48 H20 V40 H32 V32 H44 V24 H56 V56")],
    accent: [p("M12 36 L30 18 M23 18 H30 V25")],
  },
  /** A chariot wheel with nobody holding the reins. */
  wheel: {
    base: [o(34, 32, 21), o(34, 32, 17), o(34, 32, 4.5), ...wheelSpokes()],
    accent: [p("M3 26 H9 M1 32 H8 M3 38 H9")],
  },
  /** An ear of wheat with one bad grain. */
  wheat: { base: wheat.base, accent: wheat.accent },
  /** A short sword. */
  xiphos: {
    base: [
      p("M32 6 C35 14 36.5 25 34.5 40 H29.5 C27.5 25 29 14 32 6 Z"),
      p("M32 12 V39"),
      p("M23 40 H41 V43 H23 Z"),
      p("M30.5 43 V53 H33.5 V43"),
      o(32, 55.5, 2.5),
    ],
  },
} satisfies Record<string, Emblem>;

export type EmblemName = keyof typeof EMBLEMS;

/** One emblem per rule category, in the same order as CATEGORY_DESC. */
export const CATEGORY_EMBLEM: Record<string, EmblemName> = {
  "prompt-injection": "scroll",
  "skill-compromise": "key",
  "context-exfiltration": "amphora",
  "agent-manipulation": "lyre",
  "tool-poisoning": "kylix",
  "privilege-escalation": "steps",
  "excessive-autonomy": "wheel",
  "data-poisoning": "wheat",
  "model-abuse": "xiphos",
  "model-security": "aspis",
};
