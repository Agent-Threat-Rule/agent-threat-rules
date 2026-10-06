/**
 * scripts/lib/fn-mine-recoveries.ts
 *
 * What a candidate regex recovers among a corpus's false negatives, as the
 * FN-mine gate (scripts/fn-mine-llm.ts gateCandidates) counts it, and the
 * excerpts of those recoveries the authoring step copies into true_positives.
 *
 * Recoveries are DISTINCT attacks: the line the match sits on, compared with
 * the benchmark's artifacts removed. BrowseSafe-Bench carries verbatim copies
 * of eleven template sentences, one per placeholder address; counted per text,
 * a regex on one of them recovered 18 "misses" that are one sentence.
 *
 * Examples are excerpts around the match, not the text's start: an LLMail email
 * puts its injection past char 200 in most misses, and a true positive cut from
 * the start of the email does not fire the rule it is meant to test.
 */

/** The longest excerpt the author model is asked to copy into a true positive. */
export const AUTHOR_EXCERPT_CHARS = 180;

/** Examples kept per candidate: the author prompt shows them all. */
const MAX_EXAMPLES = 5;

/** Context added per widening step when an excerpt no longer matches on its own. */
const WIDEN_STEP = 40;

/** `re` without g/y, so exec and test hold no lastIndex between texts. */
function stateless(re: RegExp): RegExp {
  return re.global || re.sticky ? new RegExp(re.source, re.flags.replace(/[gy]/g, '')) : re;
}

/** A slice of `text` that does not start or end inside a surrogate pair. */
function wholeSlice(text: string, start: number, end: number): string {
  const from = start > 0 && /[\uDC00-\uDFFF]/.test(text[start] ?? '') ? start - 1 : start;
  const to = end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1] ?? '') ? end + 1 : end;
  return text.slice(Math.max(0, from), to);
}

/**
 * A contiguous excerpt of `text`, about `maxChars` long, centred on the first
 * match of `re` and still matched by it. A regex that needs context outside the
 * excerpt (a lookbehind, a word boundary) gets more until it matches; the whole
 * text is the last resort. Verbatim, so a true positive cut from it stays
 * payload-grounded.
 */
export function matchExcerpt(text: string, re: RegExp, maxChars: number): string {
  const rx = stateless(re);
  const m = rx.exec(text);
  if (!m) return wholeSlice(text, 0, maxChars);
  const end = m.index + m[0].length;
  for (let pad = Math.max(0, Math.floor((maxChars - m[0].length) / 2)); ; pad += WIDEN_STEP) {
    const start = Math.max(0, m.index - pad);
    const stop = Math.min(text.length, end + pad);
    const excerpt = wholeSlice(text, start, stop);
    if (rx.test(excerpt) || (start === 0 && stop === text.length)) return excerpt;
  }
}

/** The line(s) the match spans, normalized: two recoveries with one key are one attack. */
function recoveryKey(text: string, m: RegExpExecArray): string {
  const start = m.index === 0 ? 0 : text.lastIndexOf('\n', m.index - 1) + 1;
  const newline = text.indexOf('\n', m.index + m[0].length);
  return text
    .slice(start, newline === -1 ? text.length : newline)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

export interface Recoveries {
  /** Distinct attacks recovered: what minRecovers is compared with. */
  readonly recovers: number;
  /** FN texts matched, copies included. */
  readonly copies: number;
  /** One excerpt per distinct recovery, at most five, each matched by the regex. */
  readonly examples: readonly string[];
}

/**
 * What `re` recovers. `measureOn[i]` is `originals[i]` with the benchmark's
 * artifacts removed; a recovery must match both, because removing them can
 * make a boundary the real submission does not have. Excerpts come from the
 * originals, unmodified.
 */
export function countRecoveries(re: RegExp, measureOn: readonly string[], originals: readonly string[]): Recoveries {
  const rx = stateless(re);
  const keys = new Set<string>();
  const examples: string[] = [];
  let copies = 0;
  measureOn.forEach((measured, i) => {
    const original = originals[i] ?? measured;
    const hit = rx.exec(measured);
    if (!hit || !rx.test(original)) return;
    copies += 1;
    const key = recoveryKey(measured, hit);
    if (keys.has(key)) return;
    keys.add(key);
    if (examples.length < MAX_EXAMPLES) examples.push(matchExcerpt(original, rx, AUTHOR_EXCERPT_CHARS));
  });
  return { recovers: keys.size, copies, examples };
}
