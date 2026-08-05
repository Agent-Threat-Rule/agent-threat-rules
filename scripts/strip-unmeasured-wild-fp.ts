/**
 * One-time repair: remove every `wild_fp_rate` that no measurement supports.
 *
 * WHY THIS SCRIPT EXISTS
 *
 * scripts/compute-confidence.ts used to derive the field like this:
 *
 *     const fireCount = ruleHitMap.get(baseMetadata.id) ?? 0;
 *     const wildFpRate = fireCount > 0 ? (fireCount / wildSampleCount) * 100 : 0;
 *
 * `?? 0` turns "the scan report never mentions this rule" into "this rule was
 * measured at 0% false positives". That producer is fixed, but 230 rules on
 * disk still carry the zeros it — and the same reasoning applied by hand
 * elsewhere — left behind. The field gates the enforce (auto-block) lane, so
 * those rules sit one unearned zero away from auto-blocking user traffic.
 *
 * WHAT COUNTS AS SUPPORT
 *
 * data/mega-scan-report.json is the only wild-scan artifact in the repo. It
 * records `rule_hits` — the rules that FIRED — and a `rules_loaded` COUNT with
 * no roster. So the report can substantiate a rate for a rule it names, and can
 * substantiate nothing at all for a rule it does not: "evaluated and stayed
 * clean" and "never loaded, or unreachable on this event shape" are the same
 * silence. ATR-2026-00061 is the proof that the second case is real and not
 * theoretical — `wild_fp_rate: 0`, and 2,814 false positives on 5,352 benign
 * samples once someone put it on a corpus it could actually match.
 *
 * THE RULE APPLIED HERE
 *
 *   value is 0, rule not named in rule_hits  -> REMOVE (unsubstantiated)
 *   value is 0, rule named with count > 0    -> REMOVE (contradicted: it fired)
 *   value is non-zero                        -> KEEP
 *
 * Non-zero values are kept unconditionally even though this report cannot
 * substantiate them either. A non-zero rate is a positive claim that somebody
 * observed false positives, and those claims came from real runs this report
 * cannot see — the 53,577-sample scan of 2026-04-08, and the 5,352-sample
 * benign gate that caught ATR-2026-00061. Deleting a measurement is the same
 * class of error as inventing one.
 *
 * Only `wild_fp_rate` is stripped. `wild_samples` / `wild_validated` stay: they
 * are not gate inputs for the enforce lane (an absent rate already blocks
 * promotion on its own), and this script cannot prove per-rule that the run
 * they name excluded that rule. Destroying possibly-true records to repair a
 * provably-false one is the wrong trade. Their residual effect — an inflated
 * wild-validation component in the confidence score — is reported below.
 *
 * Usage: npx tsx scripts/strip-unmeasured-wild-fp.ts [--apply]
 *        (dry run by default; --apply writes)
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { deriveWildFpRate, type WildScanHit } from "../src/quality/index.js";

const RULES_DIR = join(import.meta.dirname, "..", "rules");
const MEGA_SCAN = join(
  import.meta.dirname,
  "..",
  "data",
  "mega-scan-report.json",
);

const doApply = process.argv.includes("--apply");

interface MegaScanReport {
  totals: { scanned: number };
  rule_hits: WildScanHit[];
}
const megaScan: MegaScanReport = JSON.parse(readFileSync(MEGA_SCAN, "utf-8"));

function findRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...findRuleFiles(full));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(full);
  }
  return out;
}

/** Matches the top-level `wild_fp_rate:` line, and it alone. */
const WILD_FP_LINE = /^wild_fp_rate:[ \t]*(\S+)[ \t]*$/m;
const ID_LINE = /^id:[ \t]*["']?([^"'\s]+)["']?[ \t]*$/m;

interface Outcome {
  readonly file: string;
  readonly id: string;
  readonly value: number;
  readonly action: "remove-unsubstantiated" | "remove-contradicted" | "keep";
  readonly note: string;
}

const outcomes: Outcome[] = [];

for (const file of findRuleFiles(RULES_DIR)) {
  const content = readFileSync(file, "utf-8");
  const m = WILD_FP_LINE.exec(content);
  if (m === null) continue;

  const value = Number(m[1]);
  const id = ID_LINE.exec(content)?.[1] ?? "(unknown)";
  const derivation = deriveWildFpRate(
    megaScan.rule_hits,
    id,
    megaScan.totals.scanned,
  );

  if (value !== 0) {
    outcomes.push({
      file,
      id,
      value,
      action: "keep",
      note: "non-zero — a positive claim of observed FPs from a run this report cannot see",
    });
    continue;
  }

  const action = derivation.substantiated
    ? "remove-contradicted"
    : "remove-unsubstantiated";
  const note = derivation.substantiated
    ? `declares 0% but the report says it ${derivation.reason} (=> ${derivation.fpRate}%)`
    : derivation.reason;

  outcomes.push({ file, id, value, action, note });

  if (doApply) {
    // Drop the whole line including its newline, so no blank line is left where
    // the claim used to be. Absence of the key IS the encoding for "unmeasured"
    // — see src/quality/wild-measurement.ts for why null would not work.
    const stripped = content.replace(
      new RegExp(`^wild_fp_rate:[ \\t]*\\S+[ \\t]*\\r?\\n`, "m"),
      "",
    );
    if (stripped !== content) writeFileSync(file, stripped);
  }
}

const removed = outcomes.filter((o) => o.action !== "keep");
const contradicted = outcomes.filter((o) => o.action === "remove-contradicted");
const kept = outcomes.filter((o) => o.action === "keep");

console.log("WILD_FP_RATE REPAIR");
console.log("═".repeat(72));
console.log(`  rules carrying the field       ${outcomes.length}`);
console.log(
  `  removed — unsubstantiated      ${removed.length - contradicted.length}`,
);
console.log(`  removed — contradicted by scan ${contradicted.length}`);
console.log(`  kept    — real measurements    ${kept.length}`);

if (contradicted.length > 0) {
  console.log(`\nCONTRADICTED (declared 0% while the scan recorded hits):`);
  for (const o of contradicted) console.log(`  ${o.id}  ${o.note}`);
}

console.log(`\nKEPT:`);
for (const o of kept.sort((a, b) => b.value - a.value)) {
  console.log(`  ${o.id.padEnd(18)} wild_fp_rate: ${o.value}`);
}

console.log(`\n${"═".repeat(72)}`);
console.log(
  doApply
    ? `Applied: ${removed.length} rules no longer claim an unmeasured FP rate.`
    : `DRY RUN — no files modified. Re-run with --apply to write.`,
);
