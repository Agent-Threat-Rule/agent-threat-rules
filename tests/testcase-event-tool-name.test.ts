/**
 * A tool event built from a test case always names a tool.
 *
 * buildEventFromTestCase (src/testcase-event.ts) gave a case that names no tool
 * the tool_name "", meant to keep the case's text out of tool_name.
 * src/engine.ts resolveField reads a field only when it is truthy and, on a
 * tool_call event, then falls back to event.content, so a tool_name condition
 * read the payload as the tool's name, and a rule keyed on the tool could pass
 * its cases without naming one. src/hook-handler.ts fills tool_name from the
 * host's tool call. No rule on main relies on the fallback. A tool event now
 * carries UNNAMED_TOOL when the case names no tool, and the case-sensitivity gate
 * leaves that name out of the text it checks a condition against.
 */
import { describe, it, expect } from "vitest";
import { benignSamples } from "../scripts/gate-case-sensitivity.js";
import { ATREngine } from "../src/engine.js";
import { buildEventFromTestCase } from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";

interface Condition {
  readonly field: string;
  readonly value: string;
}

function rule(source: string, conditions: readonly Condition[], id = "ATR-2026-97101"): ATRRule {
  return {
    id,
    title: "test-event probe",
    status: "experimental",
    maturity: "test",
    severity: "high",
    description: "fixture rule for the test-case event",
    author: "test",
    date: "2026/10/19",
    tags: { category: "prompt-injection", scan_target: "runtime", confidence: "high" },
    agent_source: { type: source, framework: ["any"], provider: ["any"] },
    detection: {
      condition: "any",
      conditions: conditions.map((c) => ({ field: c.field, operator: "regex", value: c.value, description: "probe" })),
    },
    response: { actions: ["alert"] },
  } as unknown as ATRRule;
}

function engineWith(r: ATRRule): ATREngine {
  const engine = new ATREngine();
  engine.addRule(r);
  return engine;
}

const fires = (r: ATRRule, tc: Record<string, unknown>): boolean =>
  engineWith(r).evaluate(buildEventFromTestCase(tc, r)).some((m) => m.rule.id === r.id);

describe("a tool event always names a tool", () => {
  const keyedOnBash = rule("tool_call", [{ field: "tool_name", value: "^bash\\b" }]);

  it("pins tool_name when the case names none, so a tool_name condition does not read the payload", () => {
    expect(fires(keyedOnBash, { input: "bash -c 'id'" })).toBe(false);
    const event = buildEventFromTestCase({ input: "bash -c 'id'" }, keyedOnBash);
    expect(event.type).toBe("tool_call");
    expect(event.fields?.["tool_name"]).toBe("atr-test-tool");
  });

  it("still matches a case that names the tool", () => {
    expect(fires(keyedOnBash, { input: "-c 'id'", tool_name: "bash" })).toBe(true);
  });

  it("pins it on a tool_response event too, and leaves an LLM event without one", () => {
    const mcp = rule("mcp_exchange", [{ field: "tool_response", value: "zebracorn" }]);
    expect(buildEventFromTestCase({ tool_response: "zebracorn" }, mcp).fields?.["tool_name"]).toBe("atr-test-tool");
    const llm = rule("llm_io", [{ field: "user_input", value: "zebracorn" }]);
    expect(buildEventFromTestCase({ input: "zebracorn" }, llm).fields?.["tool_name"]).toBe("");
  });

  it("is not text the case-sensitivity gate checks conditions against", () => {
    const withNegative = {
      ...keyedOnBash,
      test_cases: { true_positives: [], true_negatives: [{ input: "echo hi", expected: "not_triggered" }] },
    } as unknown as ATRRule;
    const texts = benignSamples(withNegative).flatMap((sample) => sample.texts);
    expect(texts).toContain("echo hi");
    expect(texts).not.toContain("atr-test-tool");
  });
});
