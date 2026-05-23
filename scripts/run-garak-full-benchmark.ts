#!/usr/bin/env npx tsx
/**
 * run-garak-full-benchmark.ts
 *
 * Evaluate ATR engine recall against the full garak probe corpus
 * extracted to data/test-corpora/garak-full/.
 *
 * Usage:
 *   npx tsx scripts/run-garak-full-benchmark.ts
 *   npx tsx scripts/run-garak-full-benchmark.ts --output data/garak-benchmark/garak-full-report.json
 *
 * Outputs:
 *   - JSON report to --output path (default: data/garak-benchmark/garak-full-report.json)
 *   - Missed prompts grouped by family to stdout
 *
 * Exit codes: 0 always (eval never throws on misses)
 */

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";
import { writeMeasurement } from "../src/measurement/write.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");

const RULES_DIR = resolve(REPO_ROOT, "rules");
const CORPUS_DIR = resolve(REPO_ROOT, "data/test-corpora/garak-full");

const args = process.argv.slice(2);
const outputArg = args.indexOf("--output");
const OUTPUT_PATH =
  outputArg >= 0
    ? resolve(REPO_ROOT, args[outputArg + 1])
    : resolve(REPO_ROOT, "data/garak-benchmark/garak-full-report.json");

// ---- Load engine ----
const engine = new ATREngine({ rulesDir: RULES_DIR });
await engine.loadRules();
const rulesLoaded = engine.getRuleCount();
console.log(`[garak-full] ATR rules loaded: ${rulesLoaded}`);

// ---- Load corpus ----
interface FamilyCorpus {
  family: string;
  count: number;
  prompts: string[];
}

interface MissRecord {
  family: string;
  promptIdx: number;
  prompt: string;
}

interface FamilyResult {
  family: string;
  total: number;
  detected: number;
  missed: number;
  recall: number;
  missed_prompts: MissRecord[];
}

const corpusFiles = readdirSync(CORPUS_DIR).filter((f) => f.endsWith(".json"));
console.log(`[garak-full] Families found: ${corpusFiles.length}`);

const allMisses: MissRecord[] = [];
const familyResults: FamilyResult[] = [];

let grandTotal = 0;
let grandDetected = 0;

for (const fname of corpusFiles.sort()) {
  const raw = readFileSync(join(CORPUS_DIR, fname), "utf-8");
  const corpus: FamilyCorpus = JSON.parse(raw);
  const { family, prompts } = corpus;

  if (!prompts || prompts.length === 0) continue;

  let detected = 0;
  const missed: MissRecord[] = [];

  for (let i = 0; i < prompts.length; i++) {
    const prompt = prompts[i];
    const event: AgentEvent = {
      type: "llm_input",
      content: prompt,
      timestamp: new Date().toISOString(),
      fields: { user_input: prompt },
    };

    const matches = engine.evaluate(event);
    if (matches.length > 0) {
      detected++;
    } else {
      missed.push({ family, promptIdx: i, prompt });
    }
  }

  const total = prompts.length;
  const recall = total > 0 ? Math.round((detected / total) * 1000) / 10 : 0;

  familyResults.push({
    family,
    total,
    detected,
    missed: missed.length,
    recall,
    missed_prompts: missed,
  });

  allMisses.push(...missed);
  grandTotal += total;
  grandDetected += detected;

  const status = missed.length === 0 ? "OK" : `${missed.length} MISS`;
  console.log(`  ${family.padEnd(30)} ${detected}/${total} (${recall}%)  ${status}`);
}

const grandRecall =
  grandTotal > 0
    ? Math.round((grandDetected / grandTotal) * 1000) / 10
    : 0;

console.log(`\n[garak-full] Grand total: ${grandDetected}/${grandTotal} = ${grandRecall}% recall`);
console.log(`[garak-full] Total misses: ${allMisses.length}`);

// ---- Build report ----
const report = {
  benchmark: "ATR vs garak full probe corpus",
  date: new Date().toISOString().slice(0, 10),
  atr_rules_loaded: rulesLoaded,
  corpus_families: familyResults.length,
  grand_total: grandTotal,
  grand_detected: grandDetected,
  grand_missed: allMisses.length,
  grand_recall: grandRecall,
  by_family: familyResults.map((r) => ({
    family: r.family,
    total: r.total,
    detected: r.detected,
    missed: r.missed,
    recall: r.recall,
  })),
  // Include missed prompts (no rule matched) for cluster analysis
  missed_prompts: allMisses,
};

writeFileSync(OUTPUT_PATH, JSON.stringify(report, null, 2));
console.log(`\n[garak-full] Report written to: ${OUTPUT_PATH}`);

// Standardized Measurement file (version-pinned, immutable).
// garak-full is a 100% adversarial corpus → precision = 1 by construction,
// fp_rate undefined and recorded as 0 by convention.
const recallFraction = grandTotal > 0 ? grandDetected / grandTotal : 0;
const f1 = recallFraction === 0 ? 0 : (2 * recallFraction) / (recallFraction + 1);
const byFamilyBreakdown: Record<string, { total: number; detected: number; recall: number }> = {};
for (const r of familyResults) {
  byFamilyBreakdown[r.family] = {
    total: r.total,
    detected: r.detected,
    recall: r.total > 0 ? r.detected / r.total : 0,
  };
}
// IMPORTANT: this writes under source `garak-full` (NOT `garak`). The
// existing `garak` source is reserved for the narrower in-the-wild
// jailbreak corpus (NVIDIA red-team headline, ~666 prompts) measured by
// the legacy scripts/eval-garak.sh. Keeping them as separate measurement
// streams prevents a broad-corpus number (which ATR intentionally does
// not target every family of) from overwriting the headline.
const { measurementPath } = writeMeasurement(
  {
    source: "garak-full",
    source_version: `${familyResults.length}-families`,
    source_url: "https://github.com/NVIDIA/garak",
    samples: grandTotal,
    metrics: {
      recall: recallFraction,
      precision: 1,
      f1,
      fp_rate: 0,
    },
    confusion: {
      tp: grandDetected,
      fp: 0,
      tn: 0,
      fn: allMisses.length,
    },
    breakdown: {
      by_family: byFamilyBreakdown,
      family_count: familyResults.length,
    },
    notes: `NVIDIA garak FULL probe corpus extracted to data/test-corpora/garak-full/ (${familyResults.length} families, ${grandTotal} prompts). Distinct from the narrower 'garak' source which covers only the in-the-wild jailbreak corpus. 100% adversarial — fp_rate undefined and recorded as 0 by convention.`,
  },
  { force: true },
);
console.log(`[garak-full] Measurement: ${measurementPath}`);
