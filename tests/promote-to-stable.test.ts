/**
 * scripts/promote-to-stable.ts promotes a maturity:test rule to stable when it
 * has 0 false positives on the benign corpus. A draft rule at maturity:test
 * also has 0, on every sample, because the engine never evaluates it: that 0
 * must not promote it.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ATREngine } from "../src/engine.js";
import { splitCandidates } from "../scripts/promote-to-stable.js";

const LIVE = "ATR-2026-90051";
const DRAFT = "ATR-2026-90052";
const NOISY = "ATR-2026-90053";

/** A minimal schema-valid maturity:test rule whose single regex is `pattern`. */
function rule(id: string, status: string, pattern: string): string {
  return [
    `title: fixture ${id}`,
    `id: ${id}`,
    "rule_version: 1",
    `status: ${status}`,
    "description: fixture rule for the stable-promotion tests",
    "author: test",
    "date: 2026/10/16",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    "maturity: test",
    "severity: high",
    "tags:",
    "  category: tool-poisoning",
    "  scan_target: runtime",
    "  confidence: high",
    "agent_source:",
    "  type: llm_io",
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    "  condition: any",
    "  false_positives: []",
    "  conditions:",
    "    - field: content",
    "      operator: regex",
    `      value: '${pattern}'`,
    "      description: fixture",
    "response:",
    "  actions: [alert]",
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ].join("\n");
}

describe("splitCandidates", () => {
  it("sets a candidate the engine never evaluates aside instead of calling it clean", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-promote-stable-"));
    try {
      const files = {
        [LIVE]: join(dir, "live.yaml"),
        [DRAFT]: join(dir, "draft.yaml"),
        [NOISY]: join(dir, "noisy.yaml"),
      };
      writeFileSync(files[LIVE], rule(LIVE, "experimental", "qqq-never-in-any-sample-qqq"));
      writeFileSync(files[DRAFT], rule(DRAFT, "draft", "qqq-never-in-any-sample-qqq"));
      writeFileSync(files[NOISY], rule(NOISY, "experimental", "(?i)hello"));
      const engine = new ATREngine({ rulesDir: dir });
      await engine.loadRules();

      const split = splitCandidates(
        engine,
        [LIVE, DRAFT, NOISY].map((id) => ({ id, file: files[id] ?? "" })),
        ["hello world", "plain prose"],
      );

      expect(split.clean.map((c) => c.id)).toEqual([LIVE]);
      expect(split.dirty.map((c) => c.id)).toEqual([NOISY]);
      expect([...split.unevaluated.keys()]).toEqual([DRAFT]);
      expect(split.unevaluated.get(DRAFT)).toContain("status draft");
      expect(split.fpCounts.has(DRAFT)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * A candidate the engine evaluates can still score 0 without being measured:
 * src/corpus-event.ts fieldCoverage() names the rules whose conditions this
 * benign corpus cannot exercise (a field no sample fills, such as tool_name; a
 * method the synchronous path cannot run, such as trace). Their 0 is not
 * evidence, and promotion puts them in the enforce lane.
 */
describe("splitCandidates and conditions the corpus cannot exercise", () => {
  const PLAIN = "ATR-2026-90061";
  const TRACE = "ATR-2026-90062";
  const AND_TOOL_NAME = "ATR-2026-90063";
  const ANY_TOOL_NAME_QUIET = "ATR-2026-90064";
  const ANY_TOOL_NAME_NOISY = "ATR-2026-90065";

  const condition = (field: string, pattern: string): string[] => [
    `    - field: ${field}`,
    "      operator: regex",
    `      value: '${pattern}'`,
    "      description: fixture",
  ];

  /** A maturity:test rule with the given detection lines. */
  function ruleWith(id: string, detection: readonly string[]): string {
    return [
      `title: fixture ${id}`,
      `id: ${id}`,
      "rule_version: 1",
      "status: experimental",
      "description: fixture rule for the stable-promotion tests",
      "author: test",
      "date: 2026/10/16",
      "schema_version: '0.1'",
      "detection_tier: pattern",
      "maturity: test",
      "severity: high",
      "tags:",
      "  category: tool-poisoning",
      "  scan_target: runtime",
      "  confidence: high",
      "agent_source:",
      "  type: llm_io",
      "  framework: [any]",
      "  provider: [any]",
      "detection:",
      ...detection,
      "response:",
      "  actions: [alert]",
      "test_cases:",
      "  true_positives: []",
      "  true_negatives: []",
      "",
    ].join("\n");
  }

  it("does not call 0 FP clean when the corpus could not exercise the rule", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-promote-coverage-"));
    try {
      const sources: Record<string, string> = {
        [PLAIN]: ruleWith(PLAIN, ["  condition: any", "  conditions:", ...condition("content", "qqq-never-qqq")]),
        // The synchronous engine returns null for method: trace without an event trace.
        [TRACE]: ruleWith(TRACE, ["  method: trace", "  condition: any", "  conditions:", ...condition("content", "(?i)hello")]),
        // ANDed with a field no benign sample fills: it can never fire here.
        [AND_TOOL_NAME]: ruleWith(AND_TOOL_NAME, [
          "  condition: all",
          "  conditions:",
          ...condition("tool_name", "(?i)^bash$"),
          ...condition("content", "(?i)hello"),
        ]),
        // Partly measured: the content condition ran and found nothing; tool_name never ran.
        [ANY_TOOL_NAME_QUIET]: ruleWith(ANY_TOOL_NAME_QUIET, [
          "  condition: any",
          "  conditions:",
          ...condition("tool_name", "(?i)^bash$"),
          ...condition("content", "qqq-never-qqq"),
        ]),
        // Partly measured and it did fire: the hits are real, so it is dirty.
        [ANY_TOOL_NAME_NOISY]: ruleWith(ANY_TOOL_NAME_NOISY, [
          "  condition: any",
          "  conditions:",
          ...condition("tool_name", "(?i)^bash$"),
          ...condition("content", "(?i)hello"),
        ]),
      };
      const files: Record<string, string> = {};
      for (const [id, source] of Object.entries(sources)) {
        files[id] = join(dir, `${id}.yaml`);
        writeFileSync(files[id] as string, source);
      }
      const engine = new ATREngine({ rulesDir: dir });
      await engine.loadRules();
      expect(engine.getRules().map((r) => r.id).sort()).toEqual(Object.keys(sources).sort());

      const split = splitCandidates(
        engine,
        Object.keys(sources).map((id) => ({ id, file: files[id] ?? "" })),
        ["hello world", "plain prose"],
      );

      expect(split.clean.map((c) => c.id)).toEqual([PLAIN]);
      expect(split.dirty.map((c) => c.id)).toEqual([ANY_TOOL_NAME_NOISY]);
      expect([...split.unmeasured.keys()].sort()).toEqual([AND_TOOL_NAME, ANY_TOOL_NAME_QUIET, TRACE].sort());
      expect(split.unmeasured.get(TRACE)).toMatch(/not measured/);
      expect(split.unmeasured.get(AND_TOOL_NAME)).toMatch(/not measured.*tool_name/);
      expect(split.unmeasured.get(ANY_TOOL_NAME_QUIET)).toMatch(/partially measured.*tool_name/);
      expect(split.unevaluated.size).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
