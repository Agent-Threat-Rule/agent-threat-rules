/**
 * Differential self-check for the corpus-visibility gate.
 *
 * WHY A GATE NEEDS ONE
 *   This gate's whole claim is that "0 false positives" without a supporting
 *   measurement is worthless. A static literal analyser that nobody executes is
 *   the same defect one level up: a tool asserting things about regexes it never
 *   ran. gate-re2-portability.ts already resolved this argument for the repo by
 *   checking its static scanner against real RE2; this is the same move.
 *
 * WHAT IT CHECKS
 *   Every condition the gate calls BLIND is compiled and executed against every
 *   benign sample. Zero matches is the only acceptable result. A single match
 *   means the literal extractor over-claimed what a pattern requires, which is
 *   the one error direction that makes the gate LIE -- it would report a live
 *   rule as untestable and, worse, teach people the gate exaggerates.
 *
 *   It found exactly that on its first run: `(?:\uDB40[\uDC00-\uDC7F]){3,}` was
 *   reported blind because the parser consumed `\u` and then read `DB40` as
 *   required literal text. Fixed in scripts/lib/regex-literals.ts.
 *
 * WHAT IT DOES NOT CHECK
 *   The other direction -- a rule reported visible that is really blind. That
 *   under-claim is safe by construction (see regex-literals.ts) and proving its
 *   absence would need a real regex-emptiness decision procedure.
 *
 * COST
 *   Only blind conditions are executed, ~550 of 3,346 on main, so this is one
 *   pass of a few hundred regexes over 32M characters: ~13s. Cheap enough to
 *   run in CI, which is the point.
 */
import type { RuleVisibility } from "./visibility-scan.js";
import { needsUnicodeFlag } from "../../src/engine.js";

/** Mirrors normalizeRegex() in src/engine.ts: a LEADING inline flag group only. */
export function normalizeRegex(pattern: string): string {
  return pattern.replace(/^\(\?[imsx]+\)/, "");
}

/** Mirrors the flag choice in src/engine.ts's condition evaluation. */
export function regexFlagsFor(pattern: string): string {
  return needsUnicodeFlag(pattern) ? "iu" : "i";
}

export interface BlindViolation {
  readonly ruleId: string;
  readonly file: string;
  readonly conditionIndex: number;
  readonly pattern: string;
  /** Index into the sample list, enough to reproduce without shipping the text. */
  readonly sampleIndex: number;
}

export interface VerifyResult {
  readonly executed: number;
  readonly uncompilable: number;
  readonly violations: readonly BlindViolation[];
}

/**
 * Execute every blind condition against the corpus.
 *
 * Conditions on fields a text corpus cannot fill are skipped: they are blind
 * for a reason that has nothing to do with literal extraction, and running them
 * against sample text would test a claim nobody made.
 */
export function verifyBlindConditions(
  results: readonly RuleVisibility[],
  samples: readonly string[],
): VerifyResult {
  const violations: BlindViolation[] = [];
  let executed = 0;
  let uncompilable = 0;

  for (const rule of results) {
    rule.conditions.forEach((cond, index) => {
      if (cond.visibility > 0 || cond.note !== null) return;
      if (cond.operator !== "regex" || cond.value === "") return;
      let re: RegExp;
      try {
        re = new RegExp(normalizeRegex(cond.value), regexFlagsFor(cond.value));
      } catch {
        uncompilable += 1;
        return;
      }
      executed += 1;
      for (let i = 0; i < samples.length; i += 1) {
        if (!re.test(samples[i] as string)) continue;
        violations.push({
          ruleId: rule.id,
          file: rule.file,
          conditionIndex: index,
          pattern: cond.value,
          sampleIndex: i,
        });
        return;
      }
    });
  }
  return { executed, uncompilable, violations };
}
