/**
 * The semantic-block checks npm run validate (tests/validate-rules.ts) runs on a
 * `detection.method: semantic` rule, beyond the presence of judge_model_class,
 * prompt_template and threshold.
 *
 * WHY
 *
 * src/engine.ts runs a semantic rule's pattern fallback only when
 * `detection.semantic.fallback_method === 'pattern'`, compared exactly; without
 * a judge, any other value means the rule never fires on the synchronous path.
 * spec/atr-schema.yaml allows `pattern` or `none` and a threshold from 0 to 1,
 * and none of that was checked: "Pattern", a threshold of 7, or a pattern
 * fallback with no condition in it all validated.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { semanticDetectionErrors } from "../scripts/lib/semantic-detection-fields.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ONE_CONDITION = [{ field: "content", operator: "regex", value: "zebracorn" }];

function detection(semantic: Record<string, unknown>, conditions: unknown = ONE_CONDITION): Record<string, unknown> {
  return {
    method: "semantic",
    condition: "any",
    conditions,
    semantic: { judge_model_class: "small", prompt_template: "{{input}}", threshold: 0.7, ...semantic },
  };
}

describe("semanticDetectionErrors", () => {
  it("accepts the two fallback values the schema allows, and no fallback at all", () => {
    expect(semanticDetectionErrors(detection({ fallback_method: "pattern" }))).toEqual([]);
    expect(semanticDetectionErrors(detection({ fallback_method: "none" }))).toEqual([]);
    expect(semanticDetectionErrors(detection({}))).toEqual([]);
  });

  it("rejects any other fallback value, because the engine compares it exactly", () => {
    for (const value of ["Pattern", "pattern ", "regex", "", 1, null]) {
      const errors = semanticDetectionErrors(detection({ fallback_method: value }));
      expect(errors, JSON.stringify(value)).toEqual([expect.stringMatching(/fallback_method must be "pattern" or "none"/)]);
    }
  });

  it("rejects a threshold that is not a number from 0 to 1", () => {
    for (const value of [-0.1, 1.01, 7, "0.7", Number.NaN, Number.POSITIVE_INFINITY, null]) {
      const errors = semanticDetectionErrors(detection({ threshold: value }));
      expect(errors, String(value)).toEqual([expect.stringMatching(/threshold must be a number from 0 to 1/)]);
    }
    for (const value of [0, 0.5, 1]) {
      expect(semanticDetectionErrors(detection({ threshold: value })), String(value)).toEqual([]);
    }
  });

  it("leaves a missing threshold to the presence check that already reports it", () => {
    const d = detection({});
    delete (d.semantic as Record<string, unknown>).threshold;
    expect(semanticDetectionErrors(d)).toEqual([]);
  });

  it("rejects a pattern fallback with no condition to run", () => {
    const absent = detection({ fallback_method: "pattern" });
    delete absent.conditions;
    for (const d of [
      detection({ fallback_method: "pattern" }, []),
      detection({ fallback_method: "pattern" }, {}),
      absent,
    ]) {
      expect(semanticDetectionErrors(d), JSON.stringify(d.conditions)).toEqual([
        expect.stringMatching(/no condition/),
      ]);
    }
    expect(
      semanticDetectionErrors(detection({ fallback_method: "pattern" }, { a: { field: "content", operator: "regex", value: "x" } })),
    ).toEqual([]);
  });

  it("does not ask a rule without a pattern fallback for conditions", () => {
    expect(semanticDetectionErrors(detection({ fallback_method: "none" }, []))).toEqual([]);
  });

  it("passes every semantic rule on main", () => {
    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((e) => {
        const p = join(dir, e);
        return statSync(p).isDirectory() ? walk(p) : /\.ya?ml$/.test(e) ? [p] : [];
      });
    let semanticRules = 0;
    const failing: string[] = [];
    for (const file of walk(join(REPO_ROOT, "rules"))) {
      const doc = yaml.load(readFileSync(file, "utf-8")) as { id?: string; detection?: Record<string, unknown> };
      if (doc?.detection?.method !== "semantic") continue;
      semanticRules++;
      for (const e of semanticDetectionErrors(doc.detection)) failing.push(`${doc.id}: ${e}`);
    }
    expect(semanticRules).toBeGreaterThan(0);
    expect(failing).toEqual([]);
  });
});
