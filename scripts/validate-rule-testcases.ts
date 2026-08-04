/**
 * Validate a single rule's declared test_cases (+ evasion_tests) against the live
 * engine: every true_positive must trigger the rule, every true_negative must not.
 * Usage: npx tsx scripts/validate-rule-testcases.ts <ruleId>
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import { matchedRuleIds } from "./lib/corpus-event.js";
import { loadRulesFromDirectory } from "../src/loader.js";


const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const RULE_ID = process.argv[2] || "ATR-2026-00010";

/**
 * Canonical WIDE shape. The four-field form this script used to build
 * ({tool_name, tool_input, tool_response, user_input}) resolves NONE of
 * tool_args / agent_output / agent_message / tool_description, so every
 * condition on those fields silently evaluated to false and the rule could not
 * fire on its own declared true_positive — a harness defect that is
 * indistinguishable, in the output, from a broken rule. Widened to match the
 * shape scripts/lib/corpus-event.ts blessed for the FP gate, so that a true
 * positive is exercised on the same shape the benign corpus is charged against.
 *
 * That widening was done by copying the gate's builder. This now imports it
 * instead: a local copy drifts the moment either side is edited, and a rule must
 * never earn its detection credit on a wider presentation than the one it pays
 * its false positives on.
 */
function matched(engine: ATREngine, content: string): ReadonlySet<string> {
  return matchedRuleIds(engine, content);
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
