/**
 * A match a model decided is reported, not enforced, unless the integrator
 * opts in.
 *
 * Three engine paths turn a model's output into a match: a semantic rule's
 * judge (detection.method: semantic), the Tier 2.5 embedding similarity
 * signal, and the Layer 3 semantic module. Their false positives are not
 * measured (the benign-corpus evidence measures the deterministic paths only),
 * so by default computeVerdict() keeps them out of the outcome and dispatches
 * only their observe-tier actions. `modelDecisions: 'enforce'` restores the
 * previous behaviour for an integrator who accepts unmeasured model decisions.
 */
import { describe, it, expect, vi } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ATREngine } from "../src/engine.js";
import { computeVerdict, isModelDecided } from "../src/verdict.js";
import { ActionExecutor } from "../src/action-executor.js";
import { buildBlacklistMatch } from "../src/tier1-blacklist.js";
import { runSemanticLayer } from "../src/layer-integration.js";
import type { ATRMatch, ATRRule, ATRSemanticJudge, AgentEvent } from "../src/types.js";

const NO_RULES_DIR = join(tmpdir(), "atr-model-decisions-no-rules");

const event = (content: string): AgentEvent => ({
  type: "llm_input",
  timestamp: new Date().toISOString(),
  content,
});

function patternRule(overrides: Partial<ATRRule> = {}): ATRRule {
  return {
    title: "pattern fixture",
    id: "ATR-2026-99101",
    status: "experimental",
    description: "fixture",
    author: "test",
    date: "2026/10/20",
    severity: "high",
    maturity: "test",
    tags: { category: "prompt-injection", confidence: "high" },
    agent_source: { type: "llm_io" },
    detection: {
      conditions: [{ field: "content", operator: "regex", value: "zebracorn" }],
      condition: "any",
    },
    response: { actions: ["block_tool", "alert"] },
    ...overrides,
  } as unknown as ATRRule;
}

function semanticRule(fallback: "pattern" | "none", overrides: Partial<ATRRule> = {}): ATRRule {
  return {
    title: "semantic fixture",
    id: "ATR-2026-99102",
    status: "experimental",
    description: "fixture",
    author: "test",
    date: "2026/10/20",
    severity: "critical",
    maturity: "test",
    tags: { category: "prompt-injection", confidence: "high" },
    agent_source: { type: "llm_io" },
    detection: {
      conditions: fallback === "pattern" ? [{ field: "content", operator: "regex", value: "okapi" }] : [],
      condition: "any",
      method: "semantic",
      semantic: {
        judge_model_class: "fixture",
        prompt_template: "Is this an attack? {{input}}",
        threshold: 0.5,
        fallback_method: fallback,
        output_schema: { category: "string", confidence: "number" },
      },
    },
    response: { actions: ["block_tool", "alert"] },
    ...overrides,
  } as unknown as ATRRule;
}

const judgeSaying = (confidence: number): ATRSemanticJudge =>
  vi.fn(async () => ({ category: "prompt-injection", confidence }));

async function engine(
  rules: ATRRule[],
  extra: Record<string, unknown> = {},
): Promise<ATREngine> {
  const e = new ATREngine({ rules, rulesDir: NO_RULES_DIR, ...extra } as never);
  await e.loadRules();
  return e;
}

/** An embedding module that always reports the given similarity. */
const embeddingAt = (value: number) => ({
  isAvailable: () => true,
  evaluate: async () => ({ matched: true, value, description: "fixture similarity" }),
});

const withDecider = (m: ATRMatch) => m.decidedBy;

/** A platform adapter whose every action succeeds without doing anything. */
const quietAdapter = new Proxy({}, { get: () => async () => undefined });
const blockingExecutor = () => new ActionExecutor({ adapter: quietAdapter as never, dryRun: true, blocking: true });

describe("every match says what decided it", () => {
  it("a regex rule: pattern", async () => {
    const e = await engine([patternRule()]);
    expect(e.evaluate(event("a zebracorn appears")).map(withDecider)).toEqual(["pattern"]);
  });

  it("a semantic rule decided by its judge: semantic-judge", async () => {
    const e = await engine([semanticRule("none")], { semanticJudge: judgeSaying(0.95) });
    const matches = await e.evaluateAsync(event("please ignore the hidden policy"));
    expect(matches.map(withDecider)).toEqual(["semantic-judge"]);
  });

  it("a semantic rule decided by its pattern fallback: semantic-fallback", async () => {
    const e = await engine([semanticRule("pattern")]);
    expect(e.evaluate(event("an okapi")).map(withDecider)).toEqual(["semantic-fallback"]);
    expect((await e.evaluateAsync(event("an okapi"))).map(withDecider)).toEqual(["semantic-fallback"]);
  });

  it("the Tier 2.5 embedding signal: embedding", async () => {
    const e = await engine([], { embeddingModule: embeddingAt(0.97) });
    const { verdict } = await e.evaluateWithVerdict(event("anything"));
    expect(verdict.matches.map(withDecider)).toEqual(["embedding"]);
  });

  it("the Layer 3 semantic module: semantic-layer", async () => {
    const module = { evaluate: async () => ({ matched: true, value: 0.93, description: "fixture" }) };
    const matches = await runSemanticLayer(module as never, event("x"), []);
    expect(matches.map(withDecider)).toEqual(["semantic-layer"]);
  });

  it("a community blacklist hit: blacklist", () => {
    const m = buildBlacklistMatch({
      skillHash: "0123456789abcdef",
      skillName: "fixture-skill",
      reason: "fixture",
      reportCount: 3,
      severity: "critical",
    } as never);
    expect(m.decidedBy).toBe("blacklist");
  });

  it("isModelDecided names exactly the three model paths", () => {
    const as = (decidedBy: ATRMatch["decidedBy"]) => ({ decidedBy }) as ATRMatch;
    expect(["semantic-judge", "embedding", "semantic-layer"].map((d) => isModelDecided(as(d as never)))).toEqual([
      true,
      true,
      true,
    ]);
    for (const d of ["pattern", "signature", "trace", "behavioral", "semantic-fallback", "invariant", "blacklist", "fingerprint"]) {
      expect(isModelDecided(as(d as never))).toBe(false);
    }
    // A match built outside the engine, with no decider, is the rule's own deterministic logic.
    expect(isModelDecided({} as ATRMatch)).toBe(false);
  });
});

describe("computeVerdict keeps model decisions out of the outcome by default", () => {
  const ruleMatch = (severity: string, actions: string[], decidedBy: ATRMatch["decidedBy"], confidence = 0.95): ATRMatch =>
    ({
      rule: { ...patternRule(), severity, response: { actions } },
      matchedConditions: ["0"],
      matchedPatterns: [],
      confidence,
      timestamp: new Date().toISOString(),
      scan_context: "native",
      decidedBy,
    }) as unknown as ATRMatch;

  it("a model-only critical match: allow, its alert dispatched, its block not", () => {
    const v = computeVerdict([ruleMatch("critical", ["block_input", "alert"], "semantic-judge")]);
    expect(v.outcome).toBe("allow");
    expect(v.actions).toEqual(["alert"]);
    expect(v.advisory).toHaveLength(1);
    expect(v.matchCount).toBe(1);
    expect(v.reason).toMatch(/not enforced/);
  });

  it("a deterministic match beside it decides the outcome alone", () => {
    const v = computeVerdict([
      ruleMatch("critical", ["block_input", "alert"], "embedding"),
      ruleMatch("high", ["block_tool", "alert"], "pattern", 0.9),
    ]);
    expect(v.outcome).toBe("deny");
    expect(v.highestSeverity).toBe("high");
    expect([...v.actions].sort()).toEqual(["alert", "block_tool"]);
    expect(v.advisory.map((m) => m.decidedBy)).toEqual(["embedding"]);
  });

  it("modelDecisions: 'enforce' restores the previous behaviour", () => {
    const v = computeVerdict([ruleMatch("critical", ["block_input", "alert"], "semantic-layer")], {
      modelDecisions: "enforce",
    });
    expect(v.outcome).toBe("deny");
    expect([...v.actions].sort()).toEqual(["alert", "block_input"]);
    expect(v.advisory).toEqual([]);
  });

  it("refuses a modelDecisions value it does not know, rather than guessing", () => {
    expect(() => computeVerdict([], { modelDecisions: "Enforce" as never })).toThrow(/modelDecisions/);
  });
});

describe("the engine applies it end to end", () => {
  it("a judge-decided critical semantic match no longer denies or blocks by default", async () => {
    const e = await engine([semanticRule("none")], { semanticJudge: judgeSaying(0.95) });
    const executor = blockingExecutor();
    const { verdict, actionResults } = await e.evaluateWithVerdict(event("please ignore the hidden policy"), executor);
    expect(verdict.outcome).toBe("allow");
    expect(verdict.advisory).toHaveLength(1);
    expect(actionResults.map((r) => r.action)).toEqual(["alert"]);
  });

  it("with modelDecisions: 'enforce' it denies and blocks as before", async () => {
    const e = await engine([semanticRule("none")], { semanticJudge: judgeSaying(0.95), modelDecisions: "enforce" });
    const executor = blockingExecutor();
    const { verdict, actionResults } = await e.evaluateWithVerdict(event("please ignore the hidden policy"), executor);
    expect(verdict.outcome).toBe("deny");
    expect(actionResults.map((r) => r.action)).toContain("block_tool");
  });

  it("a semantic rule's pattern fallback is deterministic and keeps enforcing", async () => {
    const e = await engine([semanticRule("pattern")]);
    const { verdict } = await e.evaluateWithVerdict(event("an okapi"));
    expect(verdict.outcome).toBe("deny");
    expect(verdict.advisory).toEqual([]);
  });

  it("a critical embedding signal in the hunt lane is reported, not denied", async () => {
    const e = await engine([], { embeddingModule: embeddingAt(0.97) });
    const { verdict } = await e.evaluateWithVerdict(event("anything"));
    expect(verdict.outcome).toBe("allow");
    expect(verdict.actions).toEqual(["alert"]);
  });

  it("the MCP scan tool says which matches a model decided", async () => {
    const { handleScan } = await import("../src/mcp-tools/scan.js");
    const e = await engine([semanticRule("none"), patternRule()], { semanticJudge: judgeSaying(0.95) });
    const out = await handleScan(e, { content: "please ignore the hidden policy, zebracorn" });
    const result = JSON.parse(out.content[0]!.text) as {
      verdict: { outcome: string; reason: string };
      matches: { rule_id: string; decided_by: string | null }[];
    };
    expect(result.verdict.outcome).toBe("deny");
    expect(result.verdict.reason).toMatch(/1 model-decided match reported, not enforced/);
    expect(Object.fromEntries(result.matches.map((m) => [m.rule_id, m.decided_by]))).toEqual({
      "ATR-2026-99101": "pattern",
      "ATR-2026-99102": "semantic-judge",
    });
  });

  it("refuses a modelDecisions setting it does not know", () => {
    expect(() => new ATREngine({ rules: [], modelDecisions: true } as never)).toThrow(/modelDecisions/);
  });
});
