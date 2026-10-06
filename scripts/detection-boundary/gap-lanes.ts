/**
 * Six judgment-type gaps, measured against the live ruleset in all three
 * detection lanes.
 *
 * gaps.json holds, for each gap, attack lines and legitimate lines that are
 * deliberately near-identical -- in several cases byte-identical. Firing on the
 * attack line while staying silent on its legitimate twin is what "detecting
 * this gap" would mean; this harness reports how often that happens.
 *
 * Events are built by src/corpus-event.ts (matchedRuleIds), the same shape set
 * the benign-corpus FP gate charges rules against, so recall here is measured
 * on the shape the rules pay their false positives on.
 *
 * Usage: npx tsx scripts/detection-boundary/gap-lanes.ts
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { ATREngine } from "../../src/engine.js";
import { matchedRuleIds } from "../../src/corpus-event.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

interface Gap {
  readonly attack: readonly string[];
  readonly benign: readonly string[];
}

const LANES = ["hunt", "alert", "enforce"] as const;

async function main(): Promise<void> {
  const gaps = JSON.parse(readFileSync(join(HERE, "gaps.json"), "utf-8")) as Record<string, Gap>;

  for (const lane of LANES) {
    const engine = new ATREngine({ rulesDir: join(REPO_ROOT, "rules"), lane });
    await engine.loadRules();

    let caught = 0;
    let attacks = 0;
    let fired = 0;
    let legit = 0;
    const perGap: string[] = [];

    for (const [name, g] of Object.entries(gaps)) {
      let ga = 0;
      let gb = 0;
      for (const s of g.attack) {
        attacks++;
        if (matchedRuleIds(engine, s).size > 0) {
          caught++;
          ga++;
        }
      }
      for (const s of g.benign) {
        legit++;
        if (matchedRuleIds(engine, s).size > 0) {
          fired++;
          gb++;
        }
      }
      perGap.push(`${name.slice(0, 2)} atk ${ga}/${g.attack.length} legit ${gb}/${g.benign.length}`);
    }

    console.log(
      `lane=${lane.padEnd(8)} attacks caught ${caught}/${attacks}   legitimate lines fired ${fired}/${legit}`,
    );
    console.log("           " + perGap.join(" | "));
  }
}

void main();
