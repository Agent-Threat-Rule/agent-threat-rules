/**
 * Compute confidence scores for all ATR rules using the Quality Standard
 * reference implementation (src/quality/).
 *
 * This script dogfoods the library: any bug here means the library is broken.
 * Third-party adopters use the same API.
 *
 * Writes confidence, wild_validated, wild_samples, wild_fp_rate back to each
 * rule's YAML. Optionally promotes rules that meet the stable gate.
 *
 * Usage: npx tsx scripts/compute-confidence.ts [--dry-run] [--promote]
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  parseATRRule,
  computeConfidence,
  canPromote,
  deriveWildFpRate,
  type RuleMetadata,
} from "../src/quality/index.js";

const RULES_DIR = join(import.meta.dirname, "..", "rules");
const MEGA_SCAN = join(
  import.meta.dirname,
  "..",
  "data",
  "mega-scan-report.json",
);

const isDryRun = process.argv.includes("--dry-run");
const doPromote = process.argv.includes("--promote");

interface MegaScanReport {
  scan_date: string;
  rules_loaded: number;
  totals: { scanned: number; flagged: number; clean: number };
  rule_hits: Array<{ id: string; count: number }>;
}

const megaScan: MegaScanReport = JSON.parse(readFileSync(MEGA_SCAN, "utf-8"));
const wildSampleCount = megaScan.totals.scanned;
const wildValidatedDate = megaScan.scan_date.slice(0, 10).replace(/-/g, "/");

function findRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...findRuleFiles(full));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(full);
  }
  return out;
}

/**
 * Parse a rule, enrich its metadata with wild scan stats, and compute
 * a confidence score.
 */
function scoreRule(filePath: string): {
  file: string;
  metadata: RuleMetadata;
  confidence: number;
  substantiated: boolean;
  wildFpRate: number | null;
  reason: string;
  content: string;
} | null {
  try {
    const content = readFileSync(filePath, "utf-8");
    const baseMetadata = parseATRRule(content);

    // The report lists the rules that FIRED, not the rules it loaded. Silence
    // is therefore unattributable — "evaluated and clean" and "never evaluated"
    // look identical from here — so deriveWildFpRate refuses to produce a
    // number for an unnamed rule instead of the old `?? 0`. See
    // src/quality/wild-measurement.ts for the full derivation.
    const derivation = deriveWildFpRate(
      megaScan.rule_hits,
      baseMetadata.id,
      wildSampleCount,
    );

    // Score on this report's own finding when it has one; otherwise score on
    // whatever the rule already carries. Not overwriting matters: this report
    // is one skill-corpus run from 2026-04-14, and rules measured since by a
    // different corpus (ATR-2026-00061 at 52.58% on the 5,352-sample benign
    // gate) hold numbers this run cannot see and must not flatten.
    const metadata: RuleMetadata = derivation.substantiated
      ? {
          ...baseMetadata,
          wildSamples: wildSampleCount,
          wildFpRate: derivation.fpRate as number,
          wildValidatedAt: wildValidatedDate,
        }
      : baseMetadata;

    const score = computeConfidence(metadata);

    return {
      file: filePath,
      metadata,
      confidence: score.total,
      substantiated: derivation.substantiated,
      wildFpRate: derivation.fpRate,
      reason: derivation.reason,
      content,
    };
  } catch {
    return null;
  }
}

/**
 * Update or insert a top-level field in YAML content.
 * Simple string manipulation — matches the behavior of the previous script.
 */
function updateYamlField(
  content: string,
  field: string,
  value: string | number,
): string {
  const newLine = `${field}: ${typeof value === "string" ? `"${value}"` : value}`;
  const regex = new RegExp(`^${field}:.*$`, "m");
  if (regex.test(content)) {
    return content.replace(regex, newLine);
  }
  const insertPoint = content.indexOf("\ntest_cases:");
  if (insertPoint !== -1) {
    return (
      content.slice(0, insertPoint) +
      `\n${newLine}` +
      content.slice(insertPoint)
    );
  }
  return content + `\n${newLine}\n`;
}

// Main
const files = findRuleFiles(RULES_DIR);
console.log(`Found ${files.length} rule files`);
console.log(
  `Mega scan: ${wildSampleCount} skills, ${megaScan.rule_hits.length} rules fired\n`,
);

const results = files
  .map(scoreRule)
  .filter((r): r is NonNullable<typeof r> => r !== null);

let promotedCount = 0;
let updatedCount = 0;

for (const r of results) {
  if (isDryRun) continue;

  let newContent = r.content;
  newContent = updateYamlField(newContent, "confidence", r.confidence);

  // The wild-validation triple is written as a unit and ONLY when this report
  // substantiates it. Two failure modes are being avoided at once:
  //   - writing 0 for a rule the report never named (the bug this replaces);
  //   - writing wild_samples/wild_validated for such a rule, which claims a
  //     run it was not part of and still inflates the confidence score's wild
  //     validation component even with the rate withheld.
  // Unsubstantiated rules are left untouched rather than cleared, because this
  // report has no authority to erase a measurement taken by a different corpus.
  if (r.substantiated) {
    newContent = updateYamlField(
      newContent,
      "wild_validated",
      wildValidatedDate,
    );
    newContent = updateYamlField(newContent, "wild_samples", wildSampleCount);
    newContent = updateYamlField(
      newContent,
      "wild_fp_rate",
      r.wildFpRate as number,
    );
  }

  if (doPromote) {
    const decision = canPromote(r.metadata, "stable");
    if (decision.eligible) {
      newContent = updateYamlField(newContent, "status", "stable");
      newContent = updateYamlField(newContent, "maturity", "stable");
      promotedCount++;
    }
  }

  if (newContent !== r.content) {
    writeFileSync(r.file, newContent);
    updatedCount++;
  }
}

// Sort by confidence descending
results.sort((a, b) => b.confidence - a.confidence);

// Report
console.log("CONFIDENCE SCORE DISTRIBUTION");
console.log("═".repeat(70));
const bands = [
  { label: "90-100 (Very High)", min: 90, max: 101 },
  { label: "80-89  (High)     ", min: 80, max: 90 },
  { label: "60-79  (Medium)   ", min: 60, max: 80 },
  { label: "40-59  (Low)      ", min: 40, max: 60 },
  { label: "0-39   (Draft)    ", min: 0, max: 40 },
];
for (const b of bands) {
  const n = results.filter(
    (r) => r.confidence >= b.min && r.confidence < b.max,
  ).length;
  const bar = "#".repeat(Math.ceil(n / 2));
  console.log(`  ${b.label}  ${String(n).padStart(3)} ${bar}`);
}

console.log("\nTOP 10 BY CONFIDENCE:");
for (const r of results.slice(0, 10)) {
  console.log(
    `  ${r.metadata.id.padEnd(18)} confidence=${String(r.confidence).padStart(3)} ` +
      `maturity=${r.metadata.maturity.padEnd(12)} ` +
      `wild_fp_rate=${r.substantiated ? `${r.wildFpRate}%` : "unmeasured"}`,
  );
}

// Say out loud how little this report actually measured. The previous version
// printed only the 7 rules that fired and wrote a 0 for everyone else, so a
// reader saw "776 rules at 0% FP" and no hint that the number was a default.
const substantiated = results.filter((r) => r.substantiated);
console.log(`\n${"─".repeat(70)}`);
console.log("WILD FP RATE COVERAGE (this report)");
console.log(
  `  substantiated (named in rule_hits)   ${String(substantiated.length).padStart(4)}`,
);
console.log(
  `  not substantiated — field untouched  ${String(results.length - substantiated.length).padStart(4)}`,
);
console.log(
  "  A rule this report cannot substantiate keeps whatever it already had.\n" +
    "  It is NOT written as 0: the report lists rules that fired, not rules it\n" +
    "  loaded, so silence here cannot tell 'clean' from 'never evaluated'.",
);

console.log(`\n${"═".repeat(70)}`);
console.log(`Total rules: ${results.length}`);
console.log(`Updated: ${updatedCount}`);
console.log(`Promoted to stable: ${promotedCount}`);
if (isDryRun) console.log("(DRY RUN — no files modified)");
