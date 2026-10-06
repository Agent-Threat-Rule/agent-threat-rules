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
 * one key and land on the same side, so a near-copy cannot leak across.
 */
import { createHash } from 'node:crypto';
import { countRecoveries } from './fn-mine-recoveries.js';
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

/**
 * Distinct held-out texts `re` recovers, counted as the minable side is
 * (countRecoveries): with `corpus`'s benchmark artifacts removed, copies of
 * one line once. Only the count leaves this function; no held-out excerpt
 * reaches the authoring prompt.
 */
export function heldOutRecoveries(re: RegExp, heldOut: readonly string[], corpus: string): number {
  const measured = heldOut.map((t) => withoutBenchmarkArtifacts(corpus, t));
  return countRecoveries(re, measured, heldOut).recovers;
}
