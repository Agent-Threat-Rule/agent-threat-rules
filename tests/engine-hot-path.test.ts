/**
 * The three hot-path changes in src/engine.ts must be invisible in every result.
 *
 *   1. Rule lookup by id goes through an index instead of a linear find() per
 *      condition. Same answer: the first loaded rule with that id.
 *   2. normalizeUnicode() keeps a single-entry memo. Same output for any input
 *      order.
 *   3. On the SKILL.md path the engine skips rules whose verdict the compound
 *      gate has already decided ("reject"), instead of evaluating them and
 *      throwing the result away.
 *
 * (3) is the one that can go wrong quietly, so it is checked twice: through
 * synthetic rules whose outcome is known, and against skillPathBlocker(), which
 * is derived independently from the engine. The engine does not consult that
 * predicate — if it did, these checks would be the predicate agreeing with
 * itself.
 */

import { describe, it, expect } from "vitest";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine, normalizeUnicode } from "../src/engine.js";
import type { ATRRule, AgentEvent } from "../src/types.js";
import { skillPathCoverage, type RuleLike } from "../scripts/lib/corpus-event.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function rule(
  id: string,
  over: {
    readonly condition?: string;
    readonly patterns?: readonly string[];
    readonly scanTarget?: string;
    readonly suppressInCodeBlocks?: boolean;
  } = {},
): ATRRule {
  const patterns = over.patterns ?? ["alpha-token", "beta-token"];
  return {
    title: `hot-path fixture ${id}`,
    id,
    status: "experimental",
    description: "fixture",
    author: "test",
    date: "2026-10-15",
    severity: "high",
    tags: {
      category: "prompt-injection",
      subcategory: "test",
      confidence: "medium",
      ...(over.scanTarget !== undefined ? { scan_target: over.scanTarget } : {}),
      ...(over.suppressInCodeBlocks !== undefined
        ? { suppress_in_code_blocks: over.suppressInCodeBlocks }
        : {}),
    },
    agent_source: { type: "llm_io" },
    detection: {
      condition: over.condition ?? "any",
      conditions: patterns.map((p) => ({
        field: "content",
        operator: "regex",
        value: p,
        description: "fixture",
      })),
    },
    response: { actions: ["alert"] },
  } as unknown as ATRRule;
}

function engineWith(...rules: ATRRule[]): ATREngine {
  const e = new ATREngine();
  for (const r of rules) e.addRule(r);
  return e;
}

const BOTH_TOKENS = "first alpha-token then beta-token";
const llmInput = (content: string): AgentEvent => ({
  type: "llm_input",
  content,
  timestamp: new Date().toISOString(),
});

describe("normalizeUnicode memo", () => {
  it("returns the right value whatever order inputs arrive in", () => {
    const zw = "ig​nore";
    const wide = "ｉｇｎｏｒｅ";
    for (let i = 0; i < 3; i++) {
      expect(normalizeUnicode(zw)).toBe("ignore");
      expect(normalizeUnicode(wide)).toBe("ignore");
      expect(normalizeUnicode("plain")).toBe("plain");
    }
    // Same content, different string object: still the memoised answer.
    expect(normalizeUnicode(["ig", "​", "nore"].join(""))).toBe("ignore");
  });
});

describe("rule lookup by id", () => {
  it("still applies a rule's own suppress_in_code_blocks tag", () => {
    const e = engineWith(rule("ATR-2026-99001", { suppressInCodeBlocks: true }));
    const inFence = "intro\n```\nalpha-token\n```\noutro";
    expect(e.evaluate(llmInput(inFence))).toHaveLength(0);
    expect(e.evaluate(llmInput("prose alpha-token prose"))).toHaveLength(1);
  });
});

describe("skill compound gate pre-check", () => {
  it("an any-mode rule outside skill|both still never fires on SKILL.md, and still fires elsewhere", async () => {
    const e = engineWith(rule("ATR-2026-99002", { scanTarget: "mcp" }));
    expect(e.scanSkill(BOTH_TOKENS)).toHaveLength(0);
    expect(await e.scanSkillAsync(BOTH_TOKENS)).toHaveLength(0);
    expect(e.evaluate(llmInput(BOTH_TOKENS))).toHaveLength(1);
  });

  it.each(["skill", "both"])("scan_target %s is evaluated on SKILL.md as before", async (target) => {
    const e = engineWith(rule("ATR-2026-99003", { scanTarget: target }));
    expect(e.scanSkill(BOTH_TOKENS).map((m) => m.rule.id)).toEqual(["ATR-2026-99003"]);
    expect((await e.scanSkillAsync(BOTH_TOKENS)).map((m) => m.rule.id)).toEqual([
      "ATR-2026-99003",
    ]);
  });

  it("an all-mode rule outside skill|both can still pass the gate, so it is not skipped", async () => {
    const e = engineWith(rule("ATR-2026-99004", { scanTarget: "mcp", condition: "all" }));
    expect(e.scanSkill(BOTH_TOKENS).map((m) => m.rule.id)).toEqual(["ATR-2026-99004"]);
    expect((await e.scanSkillAsync(BOTH_TOKENS)).map((m) => m.rule.id)).toEqual([
      "ATR-2026-99004",
    ]);
    // ...and it is still held to the gate: one matching condition is not enough.
    expect(e.scanSkill("only alpha-token here")).toHaveLength(0);
  });

  it("skips exactly rules the independent predicate calls compound-gate-unreachable", async () => {
    const e = new ATREngine({ rulesDir: join(REPO_ROOT, "rules") });
    expect(await e.loadRules()).toBeGreaterThan(0);

    const evaluated = new Set<string>();
    const internals = e as unknown as {
      evaluateRule: (r: ATRRule, ev: AgentEvent) => unknown;
    };
    const original = internals.evaluateRule.bind(e);
    internals.evaluateRule = (r, ev) => {
      evaluated.add(r.id);
      return original(r, ev);
    };
    e.scanSkill("A short benign note about formatting CSV files.");

    const rules = e.getRules() as unknown as RuleLike[];
    const active = rules.filter((r) => r.status !== "draft" && r.status !== "deprecated");
    const skipped = active.filter((r) => !evaluated.has(r.id));
    const blockerOf = new Map(skillPathCoverage(rules).map((g) => [g.ruleId, g.blocker]));

    expect(skipped.length).toBeGreaterThan(0);
    expect(
      skipped
        .filter((r) => blockerOf.get(r.id) !== "compound-gate-unreachable")
        .map((r) => r.id),
      "the engine skipped rules that skillPathBlocker() says the gate could pass",
    ).toEqual([]);
    // Nothing the predicate calls reachable may be skipped.
    for (const r of active) {
      if (!blockerOf.has(r.id)) expect(evaluated.has(r.id), r.id).toBe(true);
    }
  });
});
