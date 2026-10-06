/**
 * scripts/lib/fn-mine-heldout.ts
 *
 * The held-out half of the FN-mine gate (scripts/fn-mine-llm.ts). Each
 * corpus's uncovered false negatives are split by a stable hash of their
 * normalized text: the minable part is the only text the model sees, in mining
 * and in authoring, and the only text minRecovers is counted on; the held-out
 * part is never shown, and a candidate must also recover some of it.
 *
 * Without it, "recovers 8" was counted on the very texts the model had read.
 * A regex built from eight of them (a phrase they share, a misspelling, a
 * template line) passed the same gate as one that captures the technique, and
 * nothing told the two apart.
 *
 * The split is by content, not by position, so it does not move between runs:
 * a text held out this week is held out next week too, and no run ever shows
 * it to the model. Texts that differ only in case or whitespace normalize to
 * one key and land on the same side.
 *
 * The split is per TEXT, but different texts share lines: an LLMail
 * participant resubmits one injection under a new greeting, BrowseSafe reuses
 * template sentences. Review (2026-10-07) measured 368 of 589 held-out LLMail
 * texts and 108 of 282 BrowseSafe ones holding a 30+ character line some
 * minable text also holds, and a regex OR-ing eight shown lines "recovered" 22
 * and 7 held-out texts through them. Excluding only exact shown lines left 18
 * on LLMail: resubmissions keep a line's opening and change its tail.
 *
 * So a held-out hit counts only when the model was not shown the text around
 * it (onSeenText): not when its line is a shown line, not when the line from
 * its start through the match opens a shown line, and not when the line from
 * the match to its end closes one. What is left is a match whose line differs
 * from every shown line on both sides of it. A fragment reused inside a line
 * with new text on both sides still counts; that leak is not closed here.
 */
import { createHash } from 'node:crypto';
import { countRecoveries, lineKey } from './fn-mine-recoveries.js';
import { withoutBenchmarkArtifacts } from './fn-mine-quality.js';

/**
 * Share of each corpus's false negatives held out, in percent. 30% keeps 70%
 * for mining, where minRecovers (8 distinct texts) must still be reachable,
 * and leaves a held-out side large enough to count on: a corpus with 300
 * uncovered misses holds out about 90.
 */
export const HELD_OUT_PERCENT = 30;

/**
 * Distinct held-out texts a candidate must also recover. A candidate at the
 * minRecovers floor (8 of the 70%) that captures a technique is expected to
 * recover about 8 x 30/70 = 3.4 held-out texts; requiring 2 rejects it by
 * chance about 15% of the time (Poisson, P(X < 2) at mean 3.4), while 1 would
 * let one coincidental hit certify a memorised regex and 3 would reject a
 * real one about a third of the time. Lives here, beside the split it is
 * calibrated on, not in the miner's CLI: changing it changes what the split
 * means.
 */
export const MIN_HELD_OUT_RECOVERS = 2;

/** The text the split hashes: case and whitespace do not make a different attack. */
function splitKey(text: string): string {
  return text.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
}

/** True when `text` belongs to the held-out side. Depends on its content alone. */
export function isHeldOut(text: string): boolean {
  const bucket = createHash('sha256').update(splitKey(text)).digest().readUInt32BE(0) % 100;
  return bucket < HELD_OUT_PERCENT;
}

export interface HeldOutSplit {
  /** Shown to the model; minRecovers is counted here. */
  readonly minable: readonly string[];
  /** Never shown; MIN_HELD_OUT_RECOVERS is counted here. */
  readonly heldOut: readonly string[];
}

/** `texts` on its two sides, each in input order. */
export function splitHeldOut(texts: readonly string[]): HeldOutSplit {
  const minable: string[] = [];
  const heldOut: string[] = [];
  for (const t of texts) (isHeldOut(t) ? heldOut : minable).push(t);
  return { minable, heldOut };
}

/** The minable side's lines, as recoveries key them (lineKey, benchmark artifacts removed). */
export interface SeenText {
  readonly lines: ReadonlySet<string>;
  /** The lines, sorted: a prefix test is one binary search. */
  readonly forward: readonly string[];
  /** Each line reversed, sorted: a suffix test is a prefix test on these. */
  readonly reversed: readonly string[];
}

const reverse = (t: string): string => [...t].reverse().join('');

/** Every line of the minable texts: the text the model may have been shown. */
export function seenLines(minable: readonly string[], corpus: string): SeenText {
  const lines = new Set<string>();
  for (const t of minable) for (const l of withoutBenchmarkArtifacts(corpus, t).split('\n')) lines.add(lineKey(l));
  lines.delete('');
  const forward = [...lines].sort();
  return { lines, forward, reversed: forward.map(reverse).sort() };
}

/** True when `part` opens some string of the sorted `sorted`. */
function opensOne(sorted: readonly string[], part: string): boolean {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid] < part) lo = mid + 1;
    else hi = mid;
  }
  return lo < sorted.length && sorted[lo].startsWith(part);
}

/**
 * True when the model was shown the text around `m` in `text` (measured): a
 * spanned line is a shown line, or the first spanned line from its start
 * through the match opens a shown line, or the last from the match to its end
 * closes one.
 */
export function onSeenText(seen: SeenText, text: string, m: RegExpExecArray): boolean {
  if (seen.lines.size === 0) return false;
  const lineStart = m.index === 0 ? 0 : text.lastIndexOf('\n', m.index - 1) + 1;
  const end = m.index + m[0].length;
  const lastLineStart = m[0].includes('\n') ? text.lastIndexOf('\n', end - 1) + 1 : lineStart;
  const nl = text.indexOf('\n', end);
  const lineEnd = nl === -1 ? text.length : nl;
  const firstBreak = text.indexOf('\n', m.index);
  const firstLineEnd = firstBreak === -1 ? end : Math.min(end, firstBreak);
  const left = lineKey(text.slice(lineStart, firstLineEnd));
  const right = lineKey(text.slice(Math.max(m.index, lastLineStart), lineEnd));
  const spanned = text.slice(lineStart, lineEnd).split('\n').map(lineKey);
  return (
    spanned.some((l) => seen.lines.has(l)) ||
    (left !== '' && opensOne(seen.forward, left)) ||
    (right !== '' && opensOne(seen.reversed, reverse(right)))
  );
}

/**
 * Distinct held-out texts `re` recovers, counted as the minable side is
 * (countRecoveries): with `corpus`'s benchmark artifacts removed, copies of
 * one line once, and none on text the model was shown (onSeenText against
 * `seen`, the minable side's seenLines). Only the count leaves this function;
 * no held-out excerpt reaches the authoring prompt.
 */
export function heldOutRecoveries(re: RegExp, heldOut: readonly string[], corpus: string, seen: SeenText): number {
  const measured = heldOut.map((t) => withoutBenchmarkArtifacts(corpus, t));
  return countRecoveries(re, measured, heldOut, (text, hit) => onSeenText(seen, text, hit)).recovers;
}

/**
 * Why a corpus's split leaves nothing worth mining, or null. With fewer
 * held-out misses than MIN_HELD_OUT_RECOVERS, or fewer minable ones than
 * minRecovers, every candidate is dropped whatever the model proposes; the
 * miner skips the corpus rather than spend model calls on it, and says so.
 */
export function unmineableReason(minable: number, heldOut: number, minRecovers: number): string | null {
  if (heldOut < MIN_HELD_OUT_RECOVERS) {
    return `only ${heldOut} held-out miss${heldOut === 1 ? '' : 'es'} (< ${MIN_HELD_OUT_RECOVERS}): no candidate can pass the held-out check`;
  }
  if (minable < minRecovers) {
    return `only ${minable} minable miss${minable === 1 ? '' : 'es'} (< ${minRecovers}): no candidate can reach minRecovers`;
  }
  return null;
}
