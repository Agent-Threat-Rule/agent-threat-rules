/**
 * The test event of a declared test case, measured against what production
 * puts on an event.
 *
 * THE GAP
 *
 * buildEventFromTestCase (src/testcase-event.ts) builds the event `atr test`,
 * scripts/validate-rule-testcases.ts and the case-sensitivity gate run a case
 * on. It offers the case's input under every alias a rule might read, whatever
 * the event type: as user_input and as tool_args, and its content as
 * agent_message. src/hook-handler.ts fills tool_name, tool_args and content on a
 * tool event (and tool_response from tool_input.output or .response after the
 * tool runs); the adapters' LLM events carry content alone. A case can pass on
 * the test event only through one of those copies.
 *
 * WHAT IS PINNED
 *
 * The "runtime" field set holds what the producers put on an event of the type,
 * and caseMatchesAtRuntime runs a case on it for every event type, the engine
 * deciding which of them the rule runs on. On main no true positive needs a
 * copy: ATR-2026-01610's two cases declared as user_input match their llm_input
 * event only through the input copied into tool_args, and match a tool_response
 * event, which the engine also runs llm_io rules on and where the hook fills
 * tool_args. `atr test` lists a true positive that matches on no runtime event,
 * as passed.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";
import { ATREngine } from "../src/engine.js";
import {
  UNNAMED_TOOL,
  asTestedRule,
  buildEventFromTestCase,
  caseLabel,
  caseMatches,
  caseMatchesAtRuntime,
} from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";

const CLI = new URL("../src/cli.ts", import.meta.url).pathname;

interface Condition {
  readonly field: string;
  readonly value: string;
}

function rule(source: string, conditions: readonly Condition[], scanTarget = "runtime", id = "ATR-2026-97101"): ATRRule {
  return {
    id,
    title: "test-event probe",
    status: "experimental",
    maturity: "test",
    severity: "high",
    description: "fixture rule for the test-case event",
    author: "test",
    date: "2026/10/19",
    tags: { category: "prompt-injection", scan_target: scanTarget, confidence: "high" },
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

const runtime = (tc: Record<string, unknown>, r: ATRRule) =>
  buildEventFromTestCase(tc, r, { fields: "runtime" }).fields;

describe("the runtime field set holds what a producer puts on an event of the type", () => {
  const llm = rule("llm_io", [{ field: "tool_args", value: "zebracorn" }]);

  it("gives an llm_input event the input as user_input, never as tool_args", () => {
    expect(buildEventFromTestCase({ input: "zebracorn" }, llm).fields?.["tool_args"]).toBe("zebracorn");
    expect(runtime({ input: "zebracorn" }, llm)).toEqual({ content: "zebracorn", user_input: "zebracorn" });
    expect(runtime({ user_input: "zebracorn" }, llm)).toEqual({ content: "zebracorn", user_input: "zebracorn" });
  });

  it("gives a tool event the tool name and arguments the hook fills", () => {
    const tool = rule("tool_call", [{ field: "tool_args", value: "zebracorn" }]);
    const call = { content: "a zebracorn", tool_name: UNNAMED_TOOL, tool_args: "a zebracorn" };
    expect(runtime({ input: "a zebracorn" }, tool)).toEqual(call);
    expect(runtime({ user_input: "a zebracorn" }, tool)).toEqual(call);
    const mcp = rule("mcp_exchange", [{ field: "tool_response", value: "zebracorn" }]);
    expect(runtime({ tool_response: "zebracorn output" }, mcp)).toEqual({
      content: "zebracorn output",
      tool_response: "zebracorn output",
      tool_name: UNNAMED_TOOL,
    });
  });

  it("keeps a field the case names, on any event type", () => {
    const multi = rule("multi_agent_comm", [{ field: "tool_args", value: "zebracorn" }]);
    const named = { tool_description: "a", agent_output: "b", tool_response: "c", agent_message: "d", tool_args: "e" };
    const fields = runtime(named, multi);
    expect(fields).toMatchObject(named);
    expect(fields).not.toHaveProperty("user_input");
  });

  it("builds the event type it is asked for", () => {
    const event = buildEventFromTestCase({ input: "zebracorn" }, llm, { fields: "runtime", type: "tool_response" });
    expect(event.type).toBe("tool_response");
    expect(event.fields).toEqual({ content: "zebracorn", tool_name: UNNAMED_TOOL, tool_args: "zebracorn" });
  });

  it("leaves the default wide event as it was, apart from the tool name", () => {
    const wide = buildEventFromTestCase({ input: "zebracorn" }, llm);
    expect(wide.fields).toMatchObject({ user_input: "zebracorn", tool_args: "zebracorn", agent_message: "zebracorn", content: "zebracorn" });
  });
});

describe("a case matches at runtime on an event of any type its rule runs on", () => {
  it("accepts tool arguments an llm_io rule reads after a tool has run", () => {
    const r = rule("llm_io", [{ field: "tool_args", value: "zebracorn" }]);
    const engine = engineWith(r);
    const tc = { user_input: "a zebracorn" };
    expect(engine.evaluate(buildEventFromTestCase(tc, r, { fields: "runtime" }))).toHaveLength(0);
    expect(caseMatches(engine, r, tc)).toBe(true);
    expect(caseMatchesAtRuntime(engine, r, tc)).toBe(true);
  });

  it("rejects a case that matches only through a copy no event carries", () => {
    const toolArgs = rule("multi_agent_comm", [{ field: "tool_args", value: "zebracorn" }]);
    expect(caseMatches(engineWith(toolArgs), toolArgs, { input: "a zebracorn" })).toBe(true);
    expect(caseMatchesAtRuntime(engineWith(toolArgs), toolArgs, { input: "a zebracorn" })).toBe(false);
    expect(caseMatchesAtRuntime(engineWith(toolArgs), toolArgs, { tool_args: "a zebracorn" })).toBe(true);
    const message = rule("llm_io", [{ field: "agent_message", value: "zebracorn" }]);
    expect(caseMatches(engineWith(message), message, { input: "a zebracorn" })).toBe(true);
    expect(caseMatchesAtRuntime(engineWith(message), message, { input: "a zebracorn" })).toBe(false);
  });

  it("accepts a case its rule matches as a skill document, under either name of the input", () => {
    const skill = rule("llm_io", [{ field: "agent_message", value: "zebracorn" }], "both");
    expect(caseMatchesAtRuntime(engineWith(skill), skill, { input: "a zebracorn" })).toBe(true);
    expect(caseMatchesAtRuntime(engineWith(skill), skill, { user_input: "a zebracorn" })).toBe(true);
  });
});

describe("what atr test runs a case with", () => {
  it("puts the rule in the engine as experimental, its source type as declared", () => {
    const declared = { ...rule("context_window", [{ field: "content", value: "zebracorn" }]), status: "draft" } as ATRRule;
    const tested = asTestedRule(declared);
    expect(tested.status).toBe("experimental");
    expect(tested.agent_source.type).toBe("context_window");
    expect(declared.status).toBe("draft");
  });

  it("names a case by the payload it declares, an object as JSON", () => {
    expect(caseLabel({ user_input: "x", expected: "triggered" })).toBe("x");
    expect(caseLabel({ input: { tool_name: "bash", tool_args: "ls" } })).toBe('{"tool_name":"bash","tool_args":"ls"}');
    expect(caseLabel({ tool_description: "d" })).toBe("d");
    expect(caseLabel({ expected: "triggered" })).toBe("");
  });
});

describe("atr test reports a case that matches only through the test event's copies", () => {
  it("lists it under harnessOnly and still counts it as passed", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-runtime-parity-"));
    try {
      const rulesDir = join(dir, "rules", "prompt-injection");
      mkdirSync(rulesDir, { recursive: true });
      const fixture = {
        ...rule("multi_agent_comm", [{ field: "tool_args", value: "zebracorn" }], "runtime", "ATR-2026-97102"),
        test_cases: {
          true_positives: [
            { input: "a zebracorn attack", expected: "triggered" },
            { tool_args: "a zebracorn attack", expected: "triggered" },
          ],
          true_negatives: [{ input: "nothing to see here", expected: "not_triggered" }],
        },
      };
      writeFileSync(join(rulesDir, "ATR-2026-97102.yaml"), yaml.dump(fixture));
      const r = spawnSync("npx", ["tsx", CLI, "test", rulesDir, "--json"], { encoding: "utf8", timeout: 120_000 });
      const stdout = r.stdout ?? "";
      const start = stdout.indexOf("{");
      expect(start, `no JSON in stdout: ${stdout}${r.stderr}`).toBeGreaterThanOrEqual(0);
      const report = JSON.parse(stdout.slice(start)) as {
        passed: number;
        failed: number;
        harnessOnly?: Array<{ ruleId: string; testType: string; input: string }>;
      };
      expect(report).toMatchObject({ passed: 3, failed: 0 });
      expect(report.harnessOnly).toEqual([
        { ruleId: "ATR-2026-97102", testType: "true_positive", input: "a zebracorn attack" },
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
