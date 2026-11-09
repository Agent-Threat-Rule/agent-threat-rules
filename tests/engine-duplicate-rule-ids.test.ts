/**
 * One rule per id in the engine.
 *
 * `new ATREngine({ rules })` followed by `loadRules()` also loads the rules
 * directory (the bundled tree when none is given). When a passed rule shared
 * an id with a rule there, both were kept: the id index pointed at the passed
 * rule, but compiled patterns are keyed by id, so the directory copy's
 * patterns replaced it. The engine then matched with the directory's regex,
 * reported the passed rule's pattern text, and returned the match twice.
 * `atr test` builds its engine this way, so testing an edited copy of a rule
 * with an installed `atr` ran the published version of that rule.
 *
 * A passed rule now takes precedence over a directory rule with the same id.
 * Duplicates inside the directory are left alone: the id-collision gate and
 * the benign measurement look for them.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent, ATRRule } from "../src/types.js";

const ID = "ATR-2099-90001";

function rule(pattern: string, title: string): ATRRule {
  return {
    id: ID,
    title,
    status: "experimental",
    maturity: "test",
    severity: "high",
    description: "duplicate-id fixture",
    tags: { category: "prompt-injection" },
    agent_source: { type: "llm_io" },
    detection: { condition: "any", conditions: [{ field: "user_input", operator: "regex", value: pattern }] },
    response: { actions: ["alert"] },
    test_cases: {
      true_positives: [{ input: "x", expected: "triggered" }],
      true_negatives: [{ input: "y", expected: "not_triggered" }],
    },
  } as unknown as ATRRule;
}

const event = (content: string): AgentEvent =>
  ({ type: "llm_input", timestamp: new Date(0).toISOString(), content }) as AgentEvent;

function withRulesDir<T>(r: ATRRule, fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "atr-dup-"));
  writeFileSync(join(dir, `${ID}.yaml`), yaml.dump(r));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

describe("passed rules and the rules directory", () => {
  it("a passed rule takes precedence over a directory rule with the same id", async () => {
    await withRulesDir(rule("old-pattern", "directory copy"), async (rulesDir) => {
      const engine = new ATREngine({ rules: [rule("new-pattern", "passed copy")], rulesDir });
      expect(await engine.loadRules()).toBe(1);
      expect(engine.getRules().map((r) => r.title)).toEqual(["passed copy"]);

      const onNew = engine.evaluate(event("this has new-pattern in it"));
      expect(onNew.map((m) => m.rule.title)).toEqual(["passed copy"]);
      expect(engine.evaluate(event("this has old-pattern in it"))).toEqual([]);
    });
  });

  it("keeps duplicates inside the directory for the gates that look for them", async () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-dup-"));
    try {
      writeFileSync(join(dir, "a.yaml"), yaml.dump(rule("one-pattern", "one")));
      writeFileSync(join(dir, "b.yaml"), yaml.dump(rule("two-pattern", "two")));
      const engine = new ATREngine({ rulesDir: dir });
      expect(await engine.loadRules()).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
