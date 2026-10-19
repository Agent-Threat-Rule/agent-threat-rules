/**
 * How the site quotes an ablation reference beside a partly in-sample recall
 * figure. The figures come from the measurement file
 * (breakdown.in_sample_ablation[reference], read by lib/stats.ts), never typed.
 */
import type { BenchmarkMeasurement } from "./stats";
import { pct, pctHunt } from "./recall";

/** `28.7% (hunt) / 0.7% (enforce)`, or null when the measurement records no ablation. */
export function ablationLanes(m: Pick<BenchmarkMeasurement, "ablation">): string | null {
  if (m.ablation === null) return null;
  return `${pctHunt(m.ablation.hunt.recall)} (hunt) / ${pct(m.ablation.enforce.recall)} (enforce)`;
}

/** What the ablation reference is, and is not. */
export const ABLATION_EXPLAINED = {
  en: "the ablation reference, which approximates an out-of-sample figure but does not guarantee one: a rule that does not name the corpus can still have been tuned on it",
  zh: "這是消融參考值,接近樣本外成績但不保證是:沒有註明出自這份語料的規則,仍可能是對著它調過的",
} as const;
