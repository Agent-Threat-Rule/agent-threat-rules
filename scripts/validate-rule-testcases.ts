/**
 * Validate a single rule's declared test_cases (+ evasion_tests) against the live
 * engine: every true_positive must trigger the rule, every true_negative must not.
 * Usage: npx tsx scripts/validate-rule-testcases.ts <ruleId>
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import { loadRulesFromDirectory } from "../src/loader.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const RULE_ID = process.argv[2] || "ATR-2026-00010";

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

function matched(engine: ATREngine, content: string): Set<string> {
  const s = new Set<string>();
  for (const m of engine.evaluate(asTextEvent(content))) s.add(m.rule.id);
  for (const m of engine.scanSkill(content)) s.add(m.rule.id);
  return s;
}

async function main(): Promise<void> {
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();
  const rule = loadRulesFromDirectory(RULES_DIR).find(
    (r) => (r as { id: string }).id === RULE_ID,
  ) as Record<string, unknown> | undefined;
  if (!rule) {
    console.error(`rule ${RULE_ID} not found`);
    process.exitCode = 1;
    return;
  }
  const tc = (rule.test_cases || {}) as Record<string, unknown[]>;
  const tps = (tc.true_positives || []) as Record<string, string>[];
  const tns = (tc.true_negatives || []) as Record<string, string>[];

  let pass = 0;
  let fail = 0;
  const fails: string[] = [];
  for (const t of tps) {
    const text = t.tool_response ?? t.input ?? t.content ?? t.tool_description ?? "";
    const hit = matched(engine, text).has(RULE_ID);
    if (hit) pass++;
    else {
      fail++;
      fails.push(`TP NOT triggered: ${JSON.stringify(text).slice(0, 90)}`);
    }
  }
  for (const t of tns) {
    const text = t.tool_response ?? t.input ?? t.content ?? t.tool_description ?? "";
    const hit = matched(engine, text).has(RULE_ID);
    if (!hit) pass++;
    else {
      fail++;
      fails.push(`TN triggered (should not): ${JSON.stringify(text).slice(0, 90)}`);
    }
  }

  console.log(`${RULE_ID}: test_cases ${pass} pass / ${fail} fail (TP=${tps.length}, TN=${tns.length})`);
  for (const f of fails) console.log(`  ✗ ${f}`);
  if (fail > 0) process.exitCode = 1;
}

void main();
