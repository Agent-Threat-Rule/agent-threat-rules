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
