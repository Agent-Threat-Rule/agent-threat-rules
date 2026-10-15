/**
 * Tests for scripts/lib/semantic-compliance.ts
 *
 * The semantic lane shipped rules with no `compliance:` block, and
 * audit:mappings --require-full fails the whole corpus for every rule missing
 * one. The block it now emits is the shape scripts/fn-mine-llm.ts already
 * gets through validate:compliance: EU AI Act 15 + 9, NIST AI RMF MP.5.1 +
 * MG.3.2, ISO/IEC 42001 8.1 + 8.3. These tests pin that shape against the same
 * allowlists the validator reads, so a renamed control fails here first.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { buildComplianceTemplate } from "../scripts/lib/semantic-compliance.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");

interface Allowlist {
  readonly idField: string;
  readonly valids: Record<string, string>;
  readonly strengthValues: readonly string[];
}

function allowlist(name: string): Allowlist {
  return JSON.parse(
    readFileSync(join(REPO_ROOT, "data/compliance-frameworks", `${name}.json`), "utf-8"),
  ) as Allowlist;
}

const block = buildComplianceTemplate("Secret Key Reveal Demand in User Input", "prompt-injection");

describe("buildComplianceTemplate", () => {
  it("covers exactly the three frameworks audit:mappings --require-full checks", () => {
    expect(Object.keys(block)).toEqual(["eu_ai_act", "nist_ai_rmf", "iso_42001"]);
  });

  it("uses the gate-passing control shape with primary + secondary strength", () => {
    expect(block.eu_ai_act.map((i) => [i.article, i.strength])).toEqual([
      ["15", "primary"],
      ["9", "secondary"],
    ]);
    expect(block.nist_ai_rmf.map((i) => [i.subcategory, i.strength])).toEqual([
      ["MP.5.1", "primary"],
      ["MG.3.2", "secondary"],
    ]);
    expect(block.iso_42001.map((i) => [i.clause, i.strength])).toEqual([
      ["8.1", "primary"],
      ["8.3", "secondary"],
    ]);
  });

  it("every item passes the same checks validate:compliance applies", () => {
    for (const [framework, items] of Object.entries(block)) {
      const allow = allowlist(framework);
      for (const item of items as ReadonlyArray<Record<string, string>>) {
        const id = item[allow.idField];
        expect(typeof id).toBe("string");
        expect(id in allow.valids).toBe(true);
        expect(typeof item.context).toBe("string");
        expect(item.context.trim().length).toBeGreaterThan(40);
        expect(allow.strengthValues).toContain(item.strength);
      }
    }
  });

  it("names the rule and its category in the context prose an auditor reads", () => {
    for (const items of Object.values(block)) {
      for (const item of items as ReadonlyArray<{ context: string }>) {
        expect(item.context).toContain("Secret Key Reveal Demand in User Input");
        expect(item.context).toContain("prompt-injection");
      }
    }
  });

  it("returns a fresh object each call, so callers cannot share mutable state", () => {
    const a = buildComplianceTemplate("A", "prompt-injection");
    const b = buildComplianceTemplate("A", "prompt-injection");
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    expect(a.eu_ai_act).not.toBe(b.eu_ai_act);
  });
});
