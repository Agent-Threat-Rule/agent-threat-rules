/**
 * Full-corpus false-positive audit: run ALL loaded rules against a benign
 * JSONL corpus ({text,...} per line) and report per-rule FP counts + a
 * breakdown by rule maturity. Unlike check-rules-safety.ts (which gates only
 * the rules changed in a PR diff), this audits the ENTIRE ruleset against a
 * benign corpus — to surface existing rules that false-positive on real-world
 * skills, and to quantify how much FP a maturity filter (stable/test only)
 * would remove.
 *
 * Usage: npx tsx scripts/audit-corpus-fp.ts [path/to/corpus.jsonl]
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { ATREngine } from "../src/engine.js";
import { loadRulesFromDirectory } from "../src/loader.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const CORPUS =
  process.argv[2] || join(REPO_ROOT, "data/benign-corpus-extended/skills-sh.jsonl");

function asTextEvent(content: string): AgentEvent {
  return {
    type: "mcp_exchange",
    timestamp: new Date().toISOString(),
    content,
    fields: {
      tool_name: "corpus-sample",
      tool_input: content,
      tool_response: content,
      user_input: content,
    },
  };
}

function maturityOf(r: unknown): string {
  const o = r as Record<string, unknown>;
  if (typeof o.maturity === "string") return o.maturity;
  const meta = o.metadata as Record<string, unknown> | undefined;
  if (meta && typeof meta.maturity === "string") return meta.maturity;
  return "unknown";
}

async function main(): Promise<void> {
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();

  const rules = loadRulesFromDirectory(RULES_DIR);
  const maturity = new Map<string, string>();
  for (const r of rules) maturity.set((r as { id: string }).id, maturityOf(r));

  const lines = readFileSync(CORPUS, "utf-8").split("\n").filter((l) => l.trim());
  let samplesWithFP = 0; // either path (matches the gate's combined definition)
  let samplesScanOnly = 0; // FP via scanSkill — the path `pga scan skill.md` uses
  let samplesEvalOnly = 0; // FP via evaluate — runtime mcp_exchange path
  const perRule = new Map<string, number>();
  const perRuleScan = new Map<string, number>();
  // FP attributable ONLY to non-(stable/test) rules — i.e. removed by a maturity filter
  let samplesFPOnlyExperimental = 0;

  for (const line of lines) {
    let text: string;
    try {
      text = JSON.parse(line).text;
    } catch {
      continue;
    }
    if (!text) continue;
    const evalHits = new Set<string>();
    const scanHits = new Set<string>();
    for (const m of engine.evaluate(asTextEvent(text))) evalHits.add(m.rule.id);
    for (const m of engine.scanSkill(text)) scanHits.add(m.rule.id);
    const matched = new Set<string>([...evalHits, ...scanHits]);
    if (scanHits.size > 0) {
      samplesScanOnly++;
      for (const id of scanHits) perRuleScan.set(id, (perRuleScan.get(id) || 0) + 1);
    }
    if (evalHits.size > 0) samplesEvalOnly++;
    if (matched.size > 0) {
      samplesWithFP++;
      for (const id of matched) perRule.set(id, (perRule.get(id) || 0) + 1);
      const stableTestHit = [...matched].some((id) => {
        const m = maturity.get(id) || "unknown";
        return m === "stable" || m === "test";
      });
      if (!stableTestHit) samplesFPOnlyExperimental++;
    }
  }

  const N = lines.length;
  const sorted = [...perRule.entries()].sort((a, b) => b[1] - a[1]);
  const byMat = new Map<string, number>();
  for (const [id, c] of sorted) {
    const m = maturity.get(id) || "unknown";
    byMat.set(m, (byMat.get(m) || 0) + c);
  }

  const scanSorted = [...perRuleScan.entries()].sort((a, b) => b[1] - a[1]);
  console.log(`corpus: ${CORPUS}`);
  console.log(`rules loaded: ${rules.length}`);
  console.log(`samples: ${N}`);
  console.log(
    `FP via EITHER path (gate definition): ${samplesWithFP} (${((samplesWithFP / N) * 100).toFixed(2)}%)`,
  );
  console.log(
    `FP via scanSkill (what \`pga scan skill.md\` uses): ${samplesScanOnly} (${((samplesScanOnly / N) * 100).toFixed(2)}%)`,
  );
  console.log(
    `FP via evaluate (runtime mcp_exchange path): ${samplesEvalOnly} (${((samplesEvalOnly / N) * 100).toFixed(2)}%)`,
  );
  console.log(
    `samples FP'd ONLY by non-stable/test rules (maturity filter removes these): ${samplesFPOnlyExperimental}`,
  );
  console.log(`distinct rules FP-ing (either path): ${sorted.length}`);
  console.log(`FP hits by maturity (either path): ${JSON.stringify(Object.fromEntries(byMat))}`);
  console.log(`\nTop 30 FP-causing rules — EITHER path (id × hits × maturity):`);
  for (const [id, c] of sorted.slice(0, 30)) {
    console.log(`  ${id}  ${String(c).padStart(4)}  [${maturity.get(id) || "?"}]`);
  }
  console.log(`\nTop 20 FP-causing rules — scanSkill path ONLY (id × hits × maturity):`);
  for (const [id, c] of scanSorted.slice(0, 20)) {
    console.log(`  ${id}  ${String(c).padStart(4)}  [${maturity.get(id) || "?"}]`);
  }
}

void main();
