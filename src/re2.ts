/**
 * RE2 portability check for exporters that target RE2-family engines (Go
 * `regexp`, Rust `regex`, CEL `matches`).
 *
 * This mirrors `scanPattern` and `rewriteForRe2` in
 * scripts/audit-re2-portability.ts, which gates the rule corpus in CI. The
 * script is not part of the published package, so exporters cannot import it;
 * tests/re2-compat-parity.test.ts checks that both agree on every pattern in
 * rules/.
 *
 * @module agent-threat-rules/re2
 */

/** RE2's hard cap on a repeat bound (Go regexp/syntax maxRepeat). */
const RE2_MAX_REPEAT = 1000;

const HEX4 = /^[0-9a-fA-F]{4}$/;

/** Classes a mechanical rewrite fixes without changing what the pattern matches. */
const FIXABLE = new Set(['namedGroup', 'unicodeEscape']);

export type Re2Construct =
  | 'lookaround'
  | 'backreference'
  | 'atomicOrPossessive'
  | 'namedGroup'
  | 'unicodeEscape'
  | 'other';

interface Step {
  readonly found: readonly Re2Construct[];
  readonly next: number;
}

function scanEscape(rx: string, i: number, inClass: boolean): Step {
  const c = rx[i + 1] ?? '';
  if (c === 'u') {
    if (rx[i + 2] === '{') {
      const end = rx.indexOf('}', i + 2);
      return { found: ['unicodeEscape'], next: end === -1 ? rx.length : end + 1 };
    }
    return HEX4.test(rx.slice(i + 2, i + 6))
      ? { found: ['unicodeEscape'], next: i + 6 }
      : { found: ['other'], next: i + 2 };
  }
  if (inClass && (c === 'b' || c === 'B')) return { found: ['other'], next: i + 2 };
  if (c === 'k' && rx[i + 2] === '<') {
    const end = rx.indexOf('>', i + 2);
    return { found: ['backreference'], next: end === -1 ? rx.length : end + 1 };
  }
  if (!inClass && c >= '1' && c <= '9') return { found: ['backreference'], next: i + 2 };
  return { found: [], next: i + 2 };
}

function scanGroupOpen(rx: string, i: number): Step {
  const head4 = rx.slice(i, i + 4);
  const head3 = rx.slice(i, i + 3);
  if (head4 === '(?<=' || head4 === '(?<!') return { found: ['lookaround'], next: i + 4 };
  if (head3 === '(?=' || head3 === '(?!') return { found: ['lookaround'], next: i + 3 };
  if (head3 === '(?>') return { found: ['atomicOrPossessive'], next: i + 3 };
  if (head3 === '(?<') {
    const end = rx.indexOf('>', i + 3);
    return { found: ['namedGroup'], next: end === -1 ? rx.length : end + 1 };
  }
  return { found: [], next: i + 1 };
}

/** Index just past a quantifier starting at `i`, or null. */
function readQuantifier(rx: string, i: number): number | null {
  const ch = rx[i]!;
  const prev = i > 0 ? rx[i - 1] : '';
  if (ch === '*' || ch === '+' || ch === '?') {
    if (i === 0 || prev === '(' || prev === '|') return null;
    return rx[i + 1] === '?' ? i + 2 : i + 1;
  }
  if (ch === '{') {
    const m = /^\{\d+(,\d*)?\}/.exec(rx.slice(i));
    if (!m) return null;
    const end = i + m[0].length;
    return rx[end] === '?' ? end + 1 : end;
  }
  return null;
}

function quantifierFindings(rx: string, start: number, end: number, prevEnd: number): Re2Construct[] {
  const found: Re2Construct[] = [];
  const m = /^\{(\d+)(?:,(\d*))?\}/.exec(rx.slice(start));
  if (m && [Number(m[1]), m[2] ? Number(m[2]) : 0].some((n) => n > RE2_MAX_REPEAT)) found.push('other');
  if (rx[end] === '+' && end !== prevEnd) found.push('atomicOrPossessive');
  return found;
}

/** Every RE2-incompatible construct in a JavaScript regex source, in order. */
export function re2Constructs(rx: string): Re2Construct[] {
  const found: Re2Construct[] = [];
  let i = 0;
  let inClass = false;
  let quantEnd = -1;
  while (i < rx.length) {
    const ch = rx[i]!;
    if (ch === '\\') {
      const step = scanEscape(rx, i, inClass);
      found.push(...step.found);
      i = step.next;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      i += 1;
      continue;
    }
    if (ch === '[') {
      inClass = true;
      i += 1;
      continue;
    }
    if (ch === '(') {
      const step = scanGroupOpen(rx, i);
      found.push(...step.found);
      i = step.next;
      continue;
    }
    const quant = readQuantifier(rx, i);
    if (quant !== null) {
      found.push(...quantifierFindings(rx, i, quant, quantEnd));
      quantEnd = quant;
      i = quant;
      continue;
    }
    i += 1;
  }
  return found;
}

const isHigh = (cp: number): boolean => cp >= 0xd800 && cp <= 0xdbff;
const isLow = (cp: number): boolean => cp >= 0xdc00 && cp <= 0xdfff;
const astral = (hi: number, lo: number): number => 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
const hex4At = (rx: string, i: number): number | null =>
  rx[i] === '\\' && rx[i + 1] === 'u' && HEX4.test(rx.slice(i + 2, i + 6)) ? parseInt(rx.slice(i + 2, i + 6), 16) : null;
const cpEscape = (cp: number): string => `\\x{${cp.toString(16).toUpperCase()}}`;

/**
 * A `\uXXXX` escape at `i` in RE2 spelling, with the index after it, or null
 * when it is half of a surrogate pair that cannot be joined. JavaScript
 * without the `u` flag matches UTF-16 code units, so `😀` is one
 * character there; RE2 matches code points, where a lone surrogate never
 * matches anything.
 */
function rewriteHex4(rx: string, i: number, inClass: boolean): { out: string; next: number } | null {
  const cp = hex4At(rx, i)!;
  if (!isHigh(cp) && !isLow(cp)) return { out: `\\x{${rx.slice(i + 2, i + 6)}}`, next: i + 6 };
  if (!isHigh(cp)) return null;
  const lo = hex4At(rx, i + 6);
  if (lo !== null && isLow(lo)) return { out: cpEscape(astral(cp, lo)), next: i + 12 };
  // \uD8xx[\uDCxx-\uDCyy]: a high surrogate followed by a class of low ones.
  const range = /^\[\\u([0-9a-fA-F]{4})-\\u([0-9a-fA-F]{4})\]/.exec(rx.slice(i + 6));
  if (!inClass && range) {
    const a = parseInt(range[1]!, 16);
    const b = parseInt(range[2]!, 16);
    if (isLow(a) && isLow(b) && a <= b) {
      return { out: `[${cpEscape(astral(cp, a))}-${cpEscape(astral(cp, b))}]`, next: i + 6 + range[0].length };
    }
  }
  return null;
}

/**
 * Rewrite JS-only spellings that RE2 writes differently, walking escapes so a
 * literal backslash followed by `u2066` (`\\u2066`) is left alone. Null when
 * a surrogate escape cannot be expressed as a code point.
 */
function rewriteSpellings(rx: string): string | null {
  let out = '';
  let i = 0;
  let inClass = false;
  while (i < rx.length) {
    const ch = rx[i]!;
    if (ch === '\\') {
      const next = rx[i + 1] ?? '';
      if (next === 'u' && rx[i + 2] === '{') {
        const end = rx.indexOf('}', i + 2);
        out += `\\x{${rx.slice(i + 3, end)}}`;
        i = end + 1;
        continue;
      }
      if (hex4At(rx, i) !== null) {
        const r = rewriteHex4(rx, i, inClass);
        if (r === null) return null;
        out += r.out;
        i = r.next;
        continue;
      }
      out += ch + next;
      i += 2;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
    } else if (ch === '[') {
      inClass = true;
    } else if (ch === '(' && rx.slice(i, i + 3) === '(?<' && rx[i + 3] !== '=' && rx[i + 3] !== '!') {
      out += '(?P<';
      i += 3;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/**
 * The pattern in RE2 spelling, or null when it uses a construct RE2 cannot
 * express (lookaround, backreference, atomic or possessive, an unpaired
 * surrogate escape, and the rest).
 */
export function toRe2(rx: string): string | null {
  if (re2Constructs(rx).some((c) => !FIXABLE.has(c))) return null;
  return rewriteSpellings(rx);
}
