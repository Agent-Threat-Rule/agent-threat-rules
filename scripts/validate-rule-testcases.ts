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
import { buildEventFromTestCase } from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";


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

/** Every key a test case may carry its payload under. Order is precedence. */
const TEXT_KEYS = [
  "tool_response",
  "input",
  "content",
  "tool_description",
  "tool_args",
  "user_input",
  "agent_output",
  "agent_message",
  "tool_name",
] as const;

function testCaseText(t: Record<string, unknown>): unknown {
  for (const k of TEXT_KEYS) {
    const v = t[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return "";
}


/**
 * Did this test case fire the rule?
 *
 * Two presentations, unioned, and both applied to true NEGATIVES as well as
 * true positives — so the extra shape can never manufacture a clean pass.
 *
 *   1. The canonical shape set. This is the presentation the benign corpus is
 *      charged against, so a rule must not earn detection credit on anything
 *      wider than it.
 *   2. The field-aware event, built by the SAME function `pga test` uses. A
 *      rule whose condition reads `tool_args` cannot fire on an event carrying
 *      no tool_args; scoring that as a rule failure measures the harness, not
 *      the rule.
 *
 * Before this, only a text chain of tool_response / input / content /
 * tool_description was read. 194 test cases across 27 rules name their payload
 * under tool_args, tool_name, user_input or agent_output instead, and every one
 * of them resolved to "" — true positives reported as broken detection, true
 * negatives passing without ever being read.
 */
function firesOn(
  engine: ATREngine,
  tc: Record<string, unknown>,
  rule: ATRRule,
  text: unknown,
): boolean {
  if (matchedForInput(engine, text).has(RULE_ID)) return true;
  try {
    const event = buildEventFromTestCase(tc, rule);
    return engine.evaluate(event).some((m) => m.rule.id === RULE_ID);
  } catch {
    return false;
  }
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
    const input = testCaseText(t);
    const hit = firesOn(engine, t, rule as unknown as ATRRule, input);
    if (hit) pass++;
    else {
      fail++;
      fails.push(`TP NOT triggered: ${JSON.stringify(input).slice(0, 90)}`);
    }
  }
  for (const t of tns) {
    const input = testCaseText(t);
    const hit = firesOn(engine, t, rule as unknown as ATRRule, input);
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
