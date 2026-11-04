/**
 * holdout-report.ts — turn holdout evidence into the two things CI shows:
 * a job summary with every lane figure and its interval, and the list of
 * stable rules that do not meet the evidence bar.
 */
import type { RateWithCi } from "./binomial-ci.js";

export interface LaneFigures {
  readonly recall: { readonly overall: RateWithCi; readonly slices: Readonly<Record<string, RateWithCi>> };
  readonly fp_rate: { readonly overall: RateWithCi; readonly slices: Readonly<Record<string, RateWithCi>> };
}

export interface EvidenceRow {
  readonly id: string;
  readonly maturity: string;
  readonly recommendation: string;
  readonly failures: readonly string[];
}

const pct = (x: number): string => `${(x * 100).toFixed(2)}%`;

/** "k/n = r% [lo%, hi%]", or "k/n" when n is 0. */
export function formatRate(r: RateWithCi): string {
  if (r.rate === null || r.ci95 === null) return `${r.k}/${r.n}`;
  return `${r.k}/${r.n} = ${pct(r.rate)} [${pct(r.ci95[0])}, ${pct(r.ci95[1])}]`;
}

export function summaryMarkdown(
  lanes: Readonly<Record<string, LaneFigures>>,
  rules: readonly EvidenceRow[],
  meta: { readonly atrVersion: string; readonly atrCommit: string; readonly corpus: Readonly<Record<string, string>> },
): string {
  const lines = [
    "## Enforce-lane evidence on holdout v1",
    "",
    `ATR ${meta.atrVersion} (${meta.atrCommit}); corpus sha256 ${Object.entries(meta.corpus)
      .map(([f, h]) => `${f} \`${h.slice(0, 12)}\``)
      .join(", ")}. Intervals are 95% Clopper-Pearson.`,
    "",
    "| Lane | Recall | FP rate |",
    "|---|---|---|",
  ];
  for (const [name, f] of Object.entries(lanes)) {
    if (!f?.recall) continue;
    lines.push(`| ${name} | ${formatRate(f.recall.overall)} | ${formatRate(f.fp_rate.overall)} |`);
  }
  const counts = new Map<string, number>();
  for (const r of rules) counts.set(`${r.maturity} → ${r.recommendation}`, (counts.get(`${r.maturity} → ${r.recommendation}`) ?? 0) + 1);
  lines.push("", "| Rules | Count |", "|---|---:|");
  for (const [k, n] of [...counts].sort()) lines.push(`| ${k} | ${n} |`);
  return lines.join("\n") + "\n";
}

/** Live stable rules whose evidence does not meet the bar for a reason beyond missing evasion tests. */
export function stableShortfalls(rules: readonly EvidenceRow[]): readonly EvidenceRow[] {
  return rules.filter((r) => r.maturity === "stable" && r.recommendation.startsWith("demote"));
}
