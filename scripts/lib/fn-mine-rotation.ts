/**
 * scripts/lib/fn-mine-rotation.ts
 *
 * Which corpora the daily FN-mine cron mines. Until 2026-11-09 the daily cron
 * mined one hard-coded corpus (nemotron-agentic-ipi) and Thursday mined every
 * corpus. With every vendored attack corpus now mined (MINED_CORPORA), mining
 * all of them in one job would run past GitHub's six-hour limit, and a corpus
 * not in the hard-coded list was never mined except on Thursdays.
 *
 * So the corpora are dealt round-robin into seven buckets, one per weekday:
 * every corpus is mined once a week, a day's job stays a seventh of the whole,
 * and adding a corpus to MINED_CORPORA puts it on the rotation with no edit to
 * the workflow. A manual dispatch with an empty corpus list still mines all.
 */
import { MINED_CORPORA, type MinedCorpusSpec } from './fn-mine-corpora.js';

export const ROTATION_DAYS = 7;

/** The corpus names mined on `weekday` (0 = Sunday, as Date.getUTCDay). */
export function rotationFor(weekday: number, specs: readonly MinedCorpusSpec[] = MINED_CORPORA): readonly string[] {
  if (!Number.isInteger(weekday) || weekday < 0 || weekday >= ROTATION_DAYS) {
    throw new Error(`weekday must be an integer 0..6, got ${weekday}`);
  }
  return specs.filter((_, i) => i % ROTATION_DAYS === weekday).map((s) => s.name);
}

/** Every weekday's bucket, for the report and the test that every corpus is on the rotation. */
export function weeklyRotation(specs: readonly MinedCorpusSpec[] = MINED_CORPORA): readonly (readonly string[])[] {
  return Array.from({ length: ROTATION_DAYS }, (_, d) => rotationFor(d, specs));
}
