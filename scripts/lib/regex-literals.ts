/**
 * Required-literal extraction for ATR detection regexes.
 *
 * WHAT THIS COMPUTES
 *   For a regex R, the set of literal strings that ANY matching input must
 *   contain, expressed as a disjunction of conjunctions (DNF):
 *
 *       R matches s  =>  EXISTS alt IN alternatives . FORALL lit IN alt . s contains lit
 *
 *   `(?:write|append)\s+.{0,50}\bMEMORY\.md\b` yields
 *       [["memory.md","write"], ["append","memory.md"]]
 *   because a match needs "memory.md" AND one of "write"/"append".
 *
 * WHY IT EXISTS
 *   To decide whether a corpus could EVER have fired a rule. If every
 *   alternative contains at least one literal the corpus does not contain, the
 *   regex cannot match any sample in that corpus -- so a 0-false-positive
 *   result on it measured nothing.
 *
 * SOUNDNESS DIRECTION (the only property that matters)
 *   Every approximation here weakens the requirement, never strengthens it.
 *   Dropping a conjunct, treating a construct as opaque, or giving up entirely
 *   all produce a requirement that is easier to satisfy, so the caller
 *   concludes "the corpus could match this" more often than the truth.
 *   Consequence: this module can MISS a blind rule; it must not INVENT one.
 *   Every `return UNCONSTRAINED` below is that choice being made deliberately.
 *
 * CASE
 *   Literals are lowercased. Every ATR condition compiles with the `i` flag
 *   (src/engine.ts: `const flags = cond.case_sensitive ? '' : 'i'`, and no rule
 *   in the corpus sets case_sensitive). A hypothetical case-sensitive rule is
 *   still handled safely: case-insensitive counting can only find MORE corpus
 *   occurrences, which is the weakening direction above.
 *
 * WHAT IT DOES NOT DO
 *   It is not a regex engine and not a validator. It never executes a pattern,
 *   so a pattern that JavaScript refuses to compile still yields a (useless,
 *   unconstrained) answer rather than throwing.
 */

/** A disjunction of conjunctions. `[[]]` means "no literal is required". */
export type LiteralDnf = readonly (readonly string[])[];

/** Requirement of one pattern, plus whether blindness is even provable from it. */
export interface LiteralRequirement {
  readonly alternatives: LiteralDnf;
  /**
   * False when some alternative requires nothing, i.e. the pattern could match
   * a string built from characters alone. A false here is the module saying
   * "I cannot prove anything about this pattern", never "this pattern is fine".
   */
  readonly constrained: boolean;
}

/** No literal is required: the honest answer whenever analysis gives up. */
export const UNCONSTRAINED: LiteralRequirement = Object.freeze({
  alternatives: Object.freeze([Object.freeze([])]) as LiteralDnf,
  constrained: false,
});

/**
 * Cap on DNF size. A cross product past this point costs more than the answer
 * is worth, and overflowing it degrades to a weaker requirement rather than an
 * approximate one -- see andDnf/orDnf.
 */
export const MAX_ALTERNATIVES = 64;

// ---------------------------------------------------------------------------
// Pattern AST
// ---------------------------------------------------------------------------

export type PatternNode =
  | { readonly kind: "lit"; readonly text: string }
  | { readonly kind: "opaque" }
  | { readonly kind: "concat"; readonly items: readonly PatternNode[] }
  | { readonly kind: "alt"; readonly branches: readonly PatternNode[] };

const OPAQUE: PatternNode = Object.freeze({ kind: "opaque" as const });

/** Escapes that denote a character CLASS or a zero-width assertion, not a literal. */
const CLASS_ESCAPES = new Set("dDwWsSbBAZzGRXhHVv");
/** Escapes whose payload is a code point or property name we decline to decode. */
const OPAQUE_PAYLOAD_ESCAPES = new Set("uxcpPk");
const CONTROL_ESCAPES: ReadonlyMap<string, string> = new Map([
  ["n", "\n"],
  ["t", "\t"],
  ["r", "\r"],
  ["f", "\f"],
]);

interface Cursor {
  readonly src: string;
  i: number;
}

function peek(c: Cursor): string {
  return c.src[c.i] ?? "";
}

function atEnd(c: Cursor): boolean {
  return c.i >= c.src.length;
}

/** Advance past a `[...]` class, honouring a leading `]` and backslash escapes. */
function skipCharClass(c: Cursor): void {
  c.i += 1; // past '['
  if (peek(c) === "^") c.i += 1;
  if (peek(c) === "]") c.i += 1; // a ']' in first position is a literal
  while (!atEnd(c) && peek(c) !== "]") {
    if (peek(c) === "\\") c.i += 1;
    c.i += 1;
  }
  if (!atEnd(c)) c.i += 1; // past ']'
}

/** Advance past the ')' matching a group whose '(' is already consumed. */
function skipGroupBody(c: Cursor): void {
  let depth = 1;
  while (!atEnd(c) && depth > 0) {
    const ch = peek(c);
    if (ch === "\\") {
      c.i += 2;
      continue;
    }
    if (ch === "[") {
      skipCharClass(c);
      continue;
    }
    if (ch === "(") depth += 1;
    if (ch === ")") depth -= 1;
    c.i += 1;
  }
}

/** Minimum repetition count of a quantifier, or null when none follows. */
function parseQuantifierMin(c: Cursor): number | null {
  const ch = peek(c);
  if (ch === "?" || ch === "*") {
    c.i += 1;
    if (peek(c) === "?" || peek(c) === "+") c.i += 1; // lazy / possessive
    return 0;
  }
  if (ch === "+") {
    c.i += 1;
    if (peek(c) === "?" || peek(c) === "+") c.i += 1;
    return 1;
  }
  if (ch !== "{") return null;
  const m = /^\{(\d+)(,\d*)?\}/.exec(c.src.slice(c.i));
  if (m === null) return null; // a literal '{', e.g. `\w{`
  c.i += m[0].length;
  if (peek(c) === "?" || peek(c) === "+") c.i += 1;
  return Number.parseInt(m[1] ?? "0", 10);
}

const HEX = /[0-9a-fA-F]/;

/** Consume the argument of \u \x \c \p \P \k so it cannot be read as literal text. */
function skipEscapePayload(c: Cursor, escape: string): void {
  const open = peek(c);
  if (open === "{" || open === "<") {
    const close = open === "{" ? "}" : ">";
    while (!atEnd(c) && peek(c) !== close) c.i += 1;
    if (!atEnd(c)) c.i += 1;
    return;
  }
  const digits = escape === "u" ? 4 : escape === "x" ? 2 : escape === "c" ? 1 : 0;
  for (let n = 0; n < digits && !atEnd(c); n += 1) {
    if (escape !== "c" && !HEX.test(peek(c))) return;
    c.i += 1;
  }
}

function parseEscape(c: Cursor): PatternNode {
  c.i += 1; // past '\'
  if (atEnd(c)) return OPAQUE; // dangling backslash: unparseable, claim nothing
  const e = peek(c);
  c.i += 1;
  if (CLASS_ESCAPES.has(e)) return OPAQUE;
  if (e >= "0" && e <= "9") return OPAQUE; // backreference or octal
  if (OPAQUE_PAYLOAD_ESCAPES.has(e)) {
    // \uXXXX, \u{...}, \x41, \cA, \p{L}, \k<name>. The payload is not decoded --
    // it is CONSUMED. Leaving it behind is not a harmless simplification: the
    // first version stopped after `\u` and then read the `DB40` of
    // `(?:\uDB40[\uDC00-\uDC7F]){3,}` as a required literal "db40", which no
    // benign sample contains, so a live Unicode-tag rule was reported blind.
    // A differential run against the real regexes caught it (--verify-blind).
    skipEscapePayload(c, e);
    return OPAQUE;
  }
  const control = CONTROL_ESCAPES.get(e);
  if (control !== undefined) return { kind: "lit", text: control };
  return { kind: "lit", text: e }; // \. \/ \\ \- \$ ...
}

function parseGroup(c: Cursor): PatternNode {
  c.i += 1; // past '('
  if (peek(c) !== "?") return closeGroup(c, parseAlternation(c));
  const marker = c.src[c.i + 1] ?? "";
  if (marker === ":") {
    c.i += 2;
    return closeGroup(c, parseAlternation(c));
  }
  if (marker === "=" || marker === "!") {
    // Lookahead. A positive lookahead does impose a requirement; declining to
    // use it is the weakening direction, and a negative one imposes none.
    skipGroupBody(c);
    return OPAQUE;
  }
  if (marker === "<") {
    const third = c.src[c.i + 2] ?? "";
    if (third === "=" || third === "!") {
      skipGroupBody(c);
      return OPAQUE;
    }
    c.i += 2; // past '?<'
    while (!atEnd(c) && peek(c) !== ">") c.i += 1;
    if (!atEnd(c)) c.i += 1;
    return closeGroup(c, parseAlternation(c));
  }
  // Inline flags: (?i), (?im), (?i:...). src/engine.ts strips the bare form
  // before compiling; either way it constrains nothing.
  skipGroupBody(c);
  return OPAQUE;
}

function closeGroup(c: Cursor, inner: PatternNode): PatternNode {
  if (peek(c) === ")") c.i += 1;
  return inner;
}

function parseAtom(c: Cursor): PatternNode {
  const ch = peek(c);
  if (ch === "(") return parseGroup(c);
  if (ch === "[") {
    skipCharClass(c);
    return OPAQUE;
  }
  if (ch === "\\") return parseEscape(c);
  if (ch === "." || ch === "^" || ch === "$") {
    c.i += 1;
    return OPAQUE;
  }
  c.i += 1;
  return { kind: "lit", text: ch };
}

/** Merge neighbouring literal atoms so `abc` is one 3-char requirement. */
function mergeLiterals(items: readonly PatternNode[]): readonly PatternNode[] {
  const out: PatternNode[] = [];
  for (const item of items) {
    const prev = out[out.length - 1];
    if (item.kind === "lit" && prev !== undefined && prev.kind === "lit") {
      out[out.length - 1] = { kind: "lit", text: prev.text + item.text };
      continue;
    }
    out.push(item);
  }
  return out;
}

function parseSequence(c: Cursor): PatternNode {
  const items: PatternNode[] = [];
  while (!atEnd(c) && peek(c) !== "|" && peek(c) !== ")") {
    const before = c.i;
    const atom = parseAtom(c);
    const min = parseQuantifierMin(c);
    // An optional atom requires nothing. `abc?` therefore requires "ab", which
    // falls out of emitting one atom per character.
    items.push(min === 0 ? OPAQUE : atom);
    if (c.i === before) c.i += 1; // paranoia: never loop on an unconsumed char
  }
  const merged = mergeLiterals(items);
  if (merged.length === 1) return merged[0] as PatternNode;
  return { kind: "concat", items: merged };
}

function parseAlternation(c: Cursor): PatternNode {
  const branches: PatternNode[] = [parseSequence(c)];
  while (peek(c) === "|") {
    c.i += 1;
    branches.push(parseSequence(c));
  }
  if (branches.length === 1) return branches[0] as PatternNode;
  return { kind: "alt", branches };
}

export function parsePattern(pattern: string): PatternNode {
  const cursor: Cursor = { src: pattern, i: 0 };
  return parseAlternation(cursor);
}

// ---------------------------------------------------------------------------
// DNF
// ---------------------------------------------------------------------------

/** Drop duplicates and any literal implied by a longer one in the same term. */
function normalizeTerm(term: readonly string[]): readonly string[] {
  const unique = [...new Set(term.filter((l) => l.length > 0))];
  const kept = unique.filter(
    (l) => !unique.some((other) => other !== l && other.includes(l)),
  );
  return [...kept].sort();
}

function termKey(term: readonly string[]): string {
  return term.join(" ");
}

function dedupeTerms(terms: readonly (readonly string[])[]): LiteralDnf {
  const seen = new Map<string, readonly string[]>();
  for (const t of terms) {
    const n = normalizeTerm(t);
    seen.set(termKey(n), n);
  }
  return [...seen.values()];
}

/** True when the DNF permits a match with no literal at all. */
function isUnconstrained(dnf: LiteralDnf): boolean {
  return dnf.length === 0 || dnf.some((t) => t.length === 0);
}

/**
 * How much blindness-proving power a DNF carries: the weakest alternative's
 * best literal. Blindness needs EVERY alternative to be contradicted, so the
 * weakest one is what binds.
 */
export function dnfStrength(dnf: LiteralDnf): number {
  if (isUnconstrained(dnf)) return 0;
  let weakest = Number.POSITIVE_INFINITY;
  for (const term of dnf) {
    let best = 0;
    for (const lit of term) best = Math.max(best, lit.length);
    weakest = Math.min(weakest, best);
  }
  return weakest;
}

const UNCONSTRAINED_DNF: LiteralDnf = [[]];

/** Disjunction. Overflow collapses to "requires nothing" -- dropping a branch
 *  would STRENGTHEN the requirement, which is the one thing forbidden here. */
function orDnf(parts: readonly LiteralDnf[]): LiteralDnf {
  const terms: (readonly string[])[] = [];
  for (const p of parts) {
    if (isUnconstrained(p)) return UNCONSTRAINED_DNF;
    terms.push(...p);
    if (terms.length > MAX_ALTERNATIVES) return UNCONSTRAINED_DNF;
  }
  const merged = dedupeTerms(terms);
  return merged.length > MAX_ALTERNATIVES ? UNCONSTRAINED_DNF : merged;
}

/** Conjunction. Overflow keeps the stronger side and drops the other, which
 *  weakens the requirement -- allowed. */
function andDnf(a: LiteralDnf, b: LiteralDnf): LiteralDnf {
  if (isUnconstrained(a)) return b;
  if (isUnconstrained(b)) return a;
  if (a.length * b.length > MAX_ALTERNATIVES) {
    return dnfStrength(a) >= dnfStrength(b) ? a : b;
  }
  const product: (readonly string[])[] = [];
  for (const x of a) for (const y of b) product.push([...x, ...y]);
  const merged = dedupeTerms(product);
  return merged.length > MAX_ALTERNATIVES
    ? (dnfStrength(a) >= dnfStrength(b) ? a : b)
    : merged;
}

function dnfOf(node: PatternNode): LiteralDnf {
  switch (node.kind) {
    case "lit":
      return [[node.text.toLowerCase()]];
    case "opaque":
      return UNCONSTRAINED_DNF;
    case "alt":
      return orDnf(node.branches.map(dnfOf));
    case "concat": {
      let acc: LiteralDnf = UNCONSTRAINED_DNF;
      for (const item of node.items) acc = andDnf(acc, dnfOf(item));
      return acc;
    }
  }
}

/**
 * The literals any input matching `pattern` must contain.
 *
 * Never throws: an unparseable pattern returns UNCONSTRAINED, because "I could
 * not read it" must not be reported as "it requires nothing surprising".
 */
export function requirementOf(pattern: string): LiteralRequirement {
  let dnf: LiteralDnf;
  try {
    dnf = dnfOf(parsePattern(pattern));
  } catch {
    return UNCONSTRAINED;
  }
  if (isUnconstrained(dnf)) return UNCONSTRAINED;
  return { alternatives: dnf, constrained: true };
}

/** Every distinct literal mentioned anywhere in a requirement. */
export function literalsOf(req: LiteralRequirement): readonly string[] {
  const out = new Set<string>();
  for (const term of req.alternatives) for (const lit of term) out.add(lit);
  return [...out];
}
