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

/**
 * A test case's `input:` is not always a string.
 *
 * Rules whose detection is field-shaped (ATR-2026-00061, ATR-2026-00063, and
 * every other tool_call rule authored the same way) declare it as a MAP:
 *
 *     - input:
 *         tool_name: "file_reader"
 *         tool_args: '{"path": "/home/user/.aws/credentials"}'
 *
 * The string path then handed that object straight to matchedRuleIds(), whose
 * first act is text.normalize() — so the script died with
 * "TypeError: text.normalize is not a function" and reported NOTHING. Not a
 * failure, not a pass: a crash, on precisely the rules whose test cases are the
 * only evidence that a field-shaped detection still works. Verified present on
 * clean origin/main (646c911dd) before this change, so no rule authored in this
 * form has ever been validated by this script.
 *
 * A map is exercised on:
 *   - the author's declared FIELDS, on each event type that can carry them.
 *     This is the production shape: src/hook-handler.ts emits exactly
 *     {tool_name, tool_args, content} on a tool_call / tool_response event.
 *   - the JSON encoding of the whole map, through the same canonical shape set
 *     the benign corpus is poured through. Symmetry is the point: the FP gate
 *     fills tool_args with a JSON encoding of the sample, so a true positive
 *     must be allowed to earn credit on that encoding and no wider.
 */
function matchedForInput(engine: ATREngine, input: unknown): ReadonlySet<string> {
  if (typeof input === "string") return matched(engine, input);
  if (input === null || typeof input !== "object") return matched(engine, String(input ?? ""));

  const fields: Record<string, string> = {};
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    fields[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  const encoded = JSON.stringify(input);

  const ids = new Set<string>(matched(engine, encoded));
  for (const type of ["tool_call", "tool_response", "mcp_exchange"] as const) {
    for (const m of engine.evaluate({
      type,
      timestamp: new Date().toISOString(),
      content: encoded,
      fields,
    })) {
      ids.add(m.rule.id);
    }
  }
  return ids;
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
  const tps = (tc.true_positives || []) as Record<string, unknown>[];
  const tns = (tc.true_negatives || []) as Record<string, unknown>[];

  let pass = 0;
  let fail = 0;
  const fails: string[] = [];
  for (const t of tps) {
    const input = t.tool_response ?? t.input ?? t.content ?? t.tool_description ?? "";
    const hit = matchedForInput(engine, input).has(RULE_ID);
    if (hit) pass++;
    else {
      fail++;
      fails.push(`TP NOT triggered: ${JSON.stringify(input).slice(0, 90)}`);
    }
  }
  for (const t of tns) {
    const input = t.tool_response ?? t.input ?? t.content ?? t.tool_description ?? "";
    const hit = matchedForInput(engine, input).has(RULE_ID);
    if (!hit) pass++;
    else {
      fail++;
      fails.push(`TN triggered (should not): ${JSON.stringify(input).slice(0, 90)}`);
    }
  }

  console.log(`${RULE_ID}: test_cases ${pass} pass / ${fail} fail (TP=${tps.length}, TN=${tns.length})`);
  for (const f of fails) console.log(`  ✗ ${f}`);
  if (fail > 0) process.exitCode = 1;
}

void main();
