/**
 * scripts/lib/fn-mine-rotation.ts
 *
 * Which corpora the scheduled FN-mine runs mine. Until 2026-11-09 the daily
 * cron mined one hard-coded corpus (nemotron-agentic-ipi) and Thursday mined
 * every corpus. With every vendored attack corpus now mined (MINED_CORPORA),
 * mining all of them in one job would run past GitHub's six-hour limit, and a
 * corpus not in the hard-coded list was never mined except on Thursdays.
 *
 * So the corpora are dealt round-robin into fourteen slots, two a day (the
 * 09:00 and 21:00 UTC runs): every corpus is mined once a week and one run
 * mines about a fourteenth of the whole. Run 42526623466 took about 23 minutes
 * per corpus, so a slot of five stays near two hours. Adding a corpus to
 * MINED_CORPORA puts it on the rotation with no edit to the workflow. A manual
 * dispatch with an empty corpus list still mines all.
 */
import { MINED_CORPORA, type MinedCorpusSpec } from './fn-mine-corpora.js';

export const ROTATION_DAYS = 7;
export const RUNS_PER_DAY = 2;
export const ROTATION_SLOTS = ROTATION_DAYS * RUNS_PER_DAY;

/** The slot a run at `date` mines: weekday (UTC) times two, plus one after noon UTC. */
export function slotAt(date: Date): number {
  return date.getUTCDay() * RUNS_PER_DAY + (date.getUTCHours() >= 12 ? 1 : 0);
}

/** The corpus names mined in `slot` (0 .. ROTATION_SLOTS - 1). */
export function rotationFor(slot: number, specs: readonly MinedCorpusSpec[] = MINED_CORPORA): readonly string[] {
  if (!Number.isInteger(slot) || slot < 0 || slot >= ROTATION_SLOTS) {
    throw new Error(`slot must be an integer 0..${ROTATION_SLOTS - 1}, got ${slot}`);
  }
  return specs.filter((_, i) => i % ROTATION_SLOTS === slot).map((s) => s.name);
}

/** Every slot's corpora, for the report and the test that every corpus is on the rotation. */
export function weeklyRotation(specs: readonly MinedCorpusSpec[] = MINED_CORPORA): readonly (readonly string[])[] {
  return Array.from({ length: ROTATION_SLOTS }, (_, d) => rotationFor(d, specs));
}
