/**
 * Is data/benign-fp-measurement.json still a measurement of the rules on disk?
 *
 * A false-positive count measures a DETECTION, not a rule id. Edit the
 * conditions and the number on file describes a rule that no longer exists.
 * scripts/gate-action-eligibility.ts already treats a fingerprint mismatch as
 * UNMEASURED; this reports the same check as a count, so a document citing the
 * measurement can state how much of it is still live.
 *
 * Usage: npx tsx scripts/detection-boundary/measurement-freshness.ts
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { loadRulesFromDirectory } from "../../src/loader.js";
import { detectionFingerprint } from "../../src/quality/action-eligibility.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

interface Record_ {
  readonly fp_count: number;
  readonly detection_fingerprint: string;
}

function main(): void {
  const meas = JSON.parse(
    readFileSync(join(REPO_ROOT, "data/benign-fp-measurement.json"), "utf-8"),
  ) as { commit: string; sample_count: number; rules: Record<string, Record_> };

  const rules = loadRulesFromDirectory(join(REPO_ROOT, "rules")) as unknown as Record<
    string,
    unknown
  >[];
  const byId = new Map(rules.map((r) => [String(r["id"]), r]));

  let live = 0;
  let voided = 0;
  let missing = 0;
  const voidedIds: string[] = [];

  for (const [id, rec] of Object.entries(meas.rules)) {
    const r = byId.get(id);
    if (r === undefined) {
      missing++;
      continue;
    }
    if (detectionFingerprint(r) === rec.detection_fingerprint) live++;
    else {
      voided++;
      voidedIds.push(`${id} (fp_count ${rec.fp_count} no longer describes this rule)`);
    }
  }

  console.log(`measurement commit : ${meas.commit}`);
  console.log(`samples            : ${meas.sample_count}`);
  console.log(`rules measured     : ${Object.keys(meas.rules).length}`);
  console.log(`still live         : ${live}`);
  console.log(`voided by an edit  : ${voided}`);
  console.log(`rule gone from disk: ${missing}`);
  for (const v of voidedIds.slice(0, 30)) console.log(`  ${v}`);
}

main();
