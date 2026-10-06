#!/usr/bin/env npx tsx
/**
 * adv-probe.ts — adversarial reviewer harness.
 *
 * Usage:
 *   npx tsx scripts/adv-probe.ts <RULE-ID> <samples.jsonl>
 *
 * samples.jsonl: one JSON object per line, {"name": "...", "text": "..."}
 *
 * For the named rule it prints, per condition, the requirementOf() literal DNF,
 * then drives every sample through the FULL engine on the canonical corpus
 * shapes AND the SKILL.md scan path, reporting any own-rule match.
 */
import { readFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import { corpusShapes, promptChannelShapes } from "../src/corpus-event.js";
import { requirementOf } from "./lib/regex-literals.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

interface Sample {
  name: string;
  text: string;
}

async function main(): Promise<void> {
  const [ruleId, samplePath] = process.argv.slice(2);
  if (!ruleId || !samplePath) {
    console.error("usage: adv-probe.ts <RULE-ID> <samples.jsonl>");
    process.exit(2);
  }

  const engine = new ATREngine({ rulesDir: join(REPO_ROOT, "rules") });
  await engine.loadRules();
  const rule = engine.getRules().find((r) => r.id === ruleId);
  if (!rule) {
    console.error(`rule ${ruleId} not loaded`);
    process.exit(2);
  }

  console.log(`=== ${rule.id} — ${rule.title}`);
  console.log(`rules loaded: ${engine.getRules().length}`);
  const conds = (rule.detection as { conditions?: unknown }).conditions;
  if (Array.isArray(conds)) {
    conds.forEach((c, i) => {
      const cond = c as { field?: string; operator?: string; value?: string };
      console.log(`\n--- condition[${i}] field=${cond.field} op=${cond.operator}`);
      if (cond.operator === "regex" && typeof cond.value === "string") {
        const req = requirementOf(cond.value);
        console.log(`    constrained=${req.constrained}`);
        req.alternatives.forEach((alt, j) => {
          console.log(`    alt${j}: ${JSON.stringify([...alt])}`);
        });
      }
    });
  }

  const samples: Sample[] = readFileSync(resolve(samplePath), "utf-8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Sample);

  console.log(`\n=== running ${samples.length} samples through the live engine`);
  let fired = 0;
  for (const s of samples) {
    const hits: string[] = [];
    for (const shape of corpusShapes(s.text)) {
      for (const m of engine.evaluate(shape.event)) {
        if (m.rule.id === ruleId)
          hits.push(`${shape.name}: ${JSON.stringify(m.matchedPatterns).slice(0, 200)}`);
      }
    }
    for (const shape of promptChannelShapes(s.text)) {
      for (const m of engine.evaluate(shape.event)) {
        if (m.rule.id === ruleId)
          hits.push(`${shape.name}: ${JSON.stringify(m.matchedPatterns).slice(0, 200)}`);
      }
    }
    for (const m of engine.scanSkill(s.text)) {
      if (m.rule.id === ruleId)
        hits.push(`skill-scan: ${JSON.stringify(m.matchedPatterns).slice(0, 200)}`);
    }
    if (hits.length > 0) {
      fired += 1;
      console.log(`\nFP  ${s.name}`);
      for (const h of hits) console.log(`      ${h}`);
    } else {
      console.log(`ok  ${s.name}`);
    }
  }
  console.log(`\n=== ${fired}/${samples.length} samples fired ${ruleId}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
