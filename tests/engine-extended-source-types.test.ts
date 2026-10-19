/**
 * The engine admits an extended agent_source type where its data arrives.
 *
 * THE GAP
 *
 * spec/atr-schema.yaml allows eleven agent_source types; EVENT_TYPE_TO_SOURCE in
 * src/engine.ts maps event types to five of them, and the source filter skipped
 * every rule whose type was not the event's (bar three exceptions). A rule
 * declaring context_window, memory_access, skill_lifecycle, skill_permission or
 * skill_chain therefore never ran on a typed event: on the tool_call and
 * tool_response events src/hook-handler.ts builds, ATR-2026-00070, -00075,
 * -01155 and -01774 (scan targets mcp and tool_response) and ATR-2026-00134,
 * -00157 and -02405 never fired. Only an untyped mcp_exchange event or a
 * SKILL.md scan reached them. `atr test` mapped those types to a base type
 * before loading the rule, so every one of their cases passed.
 *
 * WHAT IS PINNED
 *
 * RUNTIME_SOURCE_TYPE: context_window runs where llm_io rules run (LLM input
 * and output, and tool responses), the skill_* types where tool_call rules
 * run. memory_access is withheld (WITHHELD_SOURCE_TYPES): it still runs only on
 * an untyped event and in a SKILL.md scan. Base types are admitted exactly as
 * before. Every type the schema allows reaches some typed event, unless it is
 * agent_trace, which the trace exception admits, or withheld; so does every
 * evaluable rule on main but the two memory_access rules, listed by id. The
 * hook runs the real rules on the events it builds, and `atr test` runs a rule
 * with the type it declares and reports a withheld one as unevaluable.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";
import {
  ATREngine,
  EVENT_TYPE_TO_SOURCE,
  RUNTIME_SOURCE_TYPE,
  WITHHELD_SOURCE_TYPES,
  sourceTypeAdmits,
} from "../src/engine.js";
import { HookHandler } from "../src/hook-handler.js";
import { loadRulesFromDirectory } from "../src/loader.js";
import type { AgentEvent, ATRRule, HookInput } from "../src/types.js";

const RULES_DIR = new URL("../rules", import.meta.url).pathname;
const SCHEMA = new URL("../spec/atr-schema.yaml", import.meta.url).pathname;
const CLI = new URL("../src/cli.ts", import.meta.url).pathname;

const EXTENDED_LLM = ["context_window"] as const;
const EXTENDED_TOOL = ["skill_lifecycle", "skill_permission", "skill_chain"] as const;

function fixture(id: string, type: string, scanTarget = "runtime"): ATRRule {
  return {
    id,
    title: "extended source probe",
    status: "experimental",
    maturity: "test",
    severity: "high",
    description: "fixture rule for the source-type filter",
    author: "test",
    date: "2026/10/19",
    tags: { category: "prompt-injection", scan_target: scanTarget, confidence: "high" },
    agent_source: { type, framework: ["any"], provider: ["any"] },
    detection: {
      condition: "any",
      conditions: [{ field: "content", operator: "regex", value: "zebracorn", description: "probe" }],
    },
    response: { actions: ["alert"] },
  } as unknown as ATRRule;
}

const event = (type: AgentEvent["type"], text = "a zebracorn attack"): AgentEvent => ({
  type,
  timestamp: "2026-10-19T00:00:00.000Z",
  content: text,
  fields: { content: text },
});

function engineWith(rule: ATRRule): ATREngine {
  const engine = new ATREngine();
  engine.addRule(rule);
  return engine;
}

const fires = (engine: ATREngine, ev: AgentEvent, id: string): boolean =>
  engine.evaluate(ev).some((m) => m.rule.id === id);

describe("the source filter admits an extended type where its data arrives", () => {
  it.each(EXTENDED_LLM)("%s runs on LLM input, LLM output and tool responses, not on tool calls", (type) => {
    const engine = engineWith(fixture("ATR-2026-98001", type));
    expect(fires(engine, event("llm_input"), "ATR-2026-98001")).toBe(true);
    expect(fires(engine, event("llm_output"), "ATR-2026-98001")).toBe(true);
    expect(fires(engine, event("tool_response"), "ATR-2026-98001")).toBe(true);
    expect(fires(engine, event("tool_call"), "ATR-2026-98001")).toBe(false);
  });

  it.each(EXTENDED_TOOL)("%s runs on tool calls, not on LLM input, LLM output or tool responses", (type) => {
    const engine = engineWith(fixture("ATR-2026-98002", type));
    expect(fires(engine, event("tool_call"), "ATR-2026-98002")).toBe(true);
    expect(fires(engine, event("llm_input"), "ATR-2026-98002")).toBe(false);
    expect(fires(engine, event("llm_output"), "ATR-2026-98002")).toBe(false);
    expect(fires(engine, event("tool_response"), "ATR-2026-98002")).toBe(false);
  });

  it("withholds memory_access: it runs on no typed event", async () => {
    const engine = engineWith(fixture("ATR-2026-98009", "memory_access"));
    for (const type of ["llm_input", "llm_output", "tool_response", "tool_call"] as const) {
      expect(fires(engine, event(type), "ATR-2026-98009"), type).toBe(false);
      expect((await engine.evaluateAsync(event(type))).map((m) => m.rule.id), type).not.toContain("ATR-2026-98009");
    }
    expect(Object.hasOwn(RUNTIME_SOURCE_TYPE, "memory_access")).toBe(false);
    expect(WITHHELD_SOURCE_TYPES["memory_access"]).toMatch(/\S/);
  });

  it("is the same on the async path", async () => {
    for (const [type, admitted, refused] of [
      ["context_window", "tool_response", "tool_call"],
      ["skill_lifecycle", "tool_call", "tool_response"],
    ] as const) {
      const engine = engineWith(fixture("ATR-2026-98003", type));
      const ids = async (t: AgentEvent["type"]) => (await engine.evaluateAsync(event(t))).map((m) => m.rule.id);
      expect(await ids(admitted)).toContain("ATR-2026-98003");
      expect(await ids(refused)).not.toContain("ATR-2026-98003");
    }
  });

  it("admits a base type exactly as before", () => {
    const cases: ReadonlyArray<readonly [string, AgentEvent["type"], boolean]> = [
      ["llm_io", "llm_input", true],
      ["llm_io", "tool_response", true], // indirect prompt injection
      ["llm_io", "tool_call", false],
      ["mcp_exchange", "tool_response", true],
      ["mcp_exchange", "tool_call", true],
      ["mcp_exchange", "llm_input", false],
      ["tool_call", "tool_call", true],
      ["tool_call", "tool_response", false],
      ["multi_agent_comm", "multi_agent_message", true],
      ["multi_agent_comm", "llm_input", false],
    ];
    for (const [type, eventType, expected] of cases) {
      const engine = engineWith(fixture("ATR-2026-98004", type));
      expect(fires(engine, event(eventType), "ATR-2026-98004"), `${type} on ${eventType}`).toBe(expected);
    }
  });

  it("does not abort an evaluation on a rule without agent_source", async () => {
    // The loader requires only id, title and detection.
    const { agent_source: _dropped, ...withoutSource } = fixture("ATR-2026-98006", "llm_io") as unknown as Record<
      string,
      unknown
    >;
    const engine = new ATREngine();
    engine.addRule(withoutSource as unknown as ATRRule);
    engine.addRule(fixture("ATR-2026-98007", "llm_io"));
    for (const type of ["mcp_exchange", "llm_input", "tool_call"] as AgentEvent["type"][]) {
      expect(() => engine.evaluate(event(type)), type).not.toThrow();
      await expect(engine.evaluateAsync(event(type)), type).resolves.toBeDefined();
    }
    // An untyped event admits every rule; a typed one admits nothing without a source type.
    expect(fires(engine, event("mcp_exchange" as AgentEvent["type"]), "ATR-2026-98006")).toBe(true);
    expect(fires(engine, event("llm_input"), "ATR-2026-98006")).toBe(false);
    expect(fires(engine, event("llm_input"), "ATR-2026-98007")).toBe(true);
  });

  it("maps only a type that is a string", () => {
    const listed = fixture("ATR-2026-98008", ["context_window"] as unknown as string);
    expect(fires(engineWith(listed), event("llm_input"), "ATR-2026-98008")).toBe(false);
    expect(sourceTypeAdmits(["context_window"], "llm_io")).toBe(false);
    expect(sourceTypeAdmits(undefined, undefined)).toBe(true);
  });

  it("still admits every type on an untyped mcp_exchange event and on a SKILL.md scan", () => {
    // scan_target both: a SKILL.md scan holds a runtime rule with one condition
    // to the skill compound gate, whatever its source type.
    for (const type of [...EXTENDED_LLM, ...EXTENDED_TOOL, "memory_access", "llm_io", "tool_call"]) {
      const engine = engineWith(fixture("ATR-2026-98005", type, "both"));
      expect(fires(engine, event("mcp_exchange" as AgentEvent["type"]), "ATR-2026-98005"), type).toBe(true);
      expect(engine.scanSkill("a zebracorn attack").some((m) => m.rule.id === "ATR-2026-98005"), type).toBe(true);
    }
  });
});

describe("every agent_source type reaches an event", () => {
  const typedSources = (): string[] => [...new Set(Object.values(EVENT_TYPE_TO_SOURCE))];
  const reachable = (type: string): boolean => typedSources().some((source) => sourceTypeAdmits(type, source));

  it("every type the schema allows, but agent_trace (the trace exception admits it) and the withheld ones", () => {
    const schema = yaml.load(readFileSync(SCHEMA, "utf-8")) as {
      properties: { agent_source: { properties: { type: { enum: string[] } } } };
    };
    const types = schema.properties.agent_source.properties.type.enum;
    expect(types).toContain("context_window");
    const unreachable = types.filter((t) => !reachable(t)).sort();
    expect(unreachable).toEqual(["agent_trace", "memory_access"]);
    expect(Object.keys(WITHHELD_SOURCE_TYPES)).toEqual(["memory_access"]);
  });

  it("maps each extended type to a source some event carries, and withholds none it maps", () => {
    for (const [type, base] of Object.entries(RUNTIME_SOURCE_TYPE)) {
      expect(typedSources(), type).toContain(base);
      expect(Object.hasOwn(WITHHELD_SOURCE_TYPES, type), type).toBe(false);
    }
  });

  it("every evaluable rule on main reaches one, but the memory_access rules, listed by id", () => {
    const rules = loadRulesFromDirectory(RULES_DIR);
    expect(rules.length).toBeGreaterThan(100);
    const live = rules.filter(
      (r) =>
        r.status !== "draft" &&
        r.status !== "deprecated" &&
        String(r.maturity ?? "").trim() !== "deprecated" &&
        r.detection?.method !== "trace",
    );
    const stranded = live.filter((r) => !reachable(r.agent_source.type));
    for (const r of stranded) {
      expect(Object.hasOwn(WITHHELD_SOURCE_TYPES, r.agent_source.type), `${r.id} (${r.agent_source.type})`).toBe(true);
    }
    // By id, not by type: a new rule of a withheld type would run on no hook or
    // adapter event, and its cases would be unevaluable in atr test, so it fails
    // here until the type is mapped (WITHHELD_SOURCE_TYPES in src/engine.ts) or
    // the rule declares a type the engine runs.
    expect(stranded.map((r) => r.id).sort(), "rules of a withheld agent_source.type").toEqual([
      "ATR-2026-00075",
      "ATR-2026-01155",
    ]);
  });
});

describe("the hook runs the extended-type rules on the events it builds", () => {
  const firstCase = (id: string): Record<string, unknown> => {
    const rule = loadRulesFromDirectory(RULES_DIR).find((r) => r.id === id);
    expect(rule, id).toBeDefined();
    const tp = rule?.test_cases?.true_positives?.[0] as unknown;
    return typeof tp === "string" ? { input: tp } : (tp as Record<string, unknown>);
  };
  // The rule's own payload, under the key the test sends; fail on a moved key
  // rather than send "undefined" and fail for the wrong reason.
  const payload = (id: string, key: string): string => {
    const value = firstCase(id)[key];
    expect(typeof value, `${id} true_positives[0].${key}`).toBe("string");
    return value as string;
  };

  it("PostToolUse: a context_window rule reading tool_response (ATR-2026-00070)", async () => {
    const engine = new ATREngine({ rulesDir: RULES_DIR });
    await engine.loadRules();
    const out = await new HookHandler({ engine } as never).handlePostToolUse({
      hook_event_name: "PostToolUse",
      tool_name: "WebFetch",
      tool_input: { url: "https://example.com/doc", output: payload("ATR-2026-00070", "tool_response") },
    } as HookInput);
    expect(out.matched_rules ?? []).toContain("ATR-2026-00070");
  });

  it("PreToolUse: a skill_lifecycle rule on the content a tool writes (ATR-2026-02405)", async () => {
    const engine = new ATREngine({ rulesDir: RULES_DIR });
    await engine.loadRules();
    const out = await new HookHandler({ engine } as never).handlePreToolUse({
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: "/tmp/skills/x/SKILL.md", content: payload("ATR-2026-02405", "input") },
    } as HookInput);
    expect(out.matched_rules ?? []).toContain("ATR-2026-02405");
  });
});

describe("atr test runs a rule with the type it declares", () => {
  it("passes an extended-type rule's cases without mapping its type, and reports a withheld type", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-extended-source-"));
    try {
      const rulesDir = join(dir, "rules", "prompt-injection");
      mkdirSync(rulesDir, { recursive: true });
      for (const [i, type] of ["context_window", "skill_lifecycle", "memory_access"].entries()) {
        const rule = {
          ...fixture(`ATR-2026-9801${i}`, type),
          test_cases: {
            true_positives: [{ input: "a zebracorn attack", expected: "triggered" }],
            true_negatives: [{ input: "nothing to see here", expected: "not_triggered" }],
          },
        };
        writeFileSync(join(rulesDir, `ATR-2026-9801${i}.yaml`), yaml.dump(rule));
      }
      const r = spawnSync("npx", ["tsx", CLI, "test", rulesDir, "--json"], { encoding: "utf8", timeout: 120_000 });
      const stdout = r.stdout ?? "";
      const report = JSON.parse(stdout.slice(stdout.indexOf("{"))) as {
        passed: number;
        failed: number;
        skipped: number;
        skippedRules: Array<{ ruleId: string; cases: number; reason: string }>;
      };
      expect(report).toMatchObject({ passed: 4, failed: 0, skipped: 2 });
      expect(report.skippedRules).toEqual([
        { ruleId: "ATR-2026-98012", cases: 2, reason: expect.stringContaining("memory_access") },
      ]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
