/**
 * Tests for skillPathCoverage() — the third axis of "clean must never mean
 * never looked at it".
 *
 * THE DEFECT THESE TESTS PIN
 *
 * matchedRuleIds() runs four evaluate() shapes AND engine.scanSkill(), and
 * gate-promotion-fp prints `shapes = wide-raw, ..., skill`. That reads as "every
 * rule you are gating was offered to the SKILL.md path". It is false for 645 of
 * the 780 rules on main.
 *
 * scanSkill() sets `scanContext: 'skill'`, which makes the engine apply a
 * compound gate to every rule that is not `scan_target: skill|both`:
 *
 *     const totalConds = Number(rule.detection?.conditions?.length ?? 1);
 *     const minRequired = Math.max(2, Math.ceil(totalConds * 0.3));
 *     if ((matchResult.matchedConditions?.length ?? 0) < minRequired) continue;
 *
 * The comment beside it describes a graded "30% of conditions" threshold. It is
 * not one. `matchedConditions` comes from evaluateArrayConditions, which BREAKS
 * on the first matching condition when `condition: any` — so its length is 1
 * whenever the rule matched at all, and minRequired is never below 2. 776 of the
 * 780 rules declare `condition: any`. For them the gate is an unconditional
 * reject.
 *
 * WHY THIS IS NOT "FIXED" HERE
 *
 * Measured 2026-08-05 on this branch: stop short-circuiting in skill context and
 * the 466-sample benign skill corpus goes from 1 flagged sample to 265 (7 new
 * rules, 406 new false positives) while malicious recall stays 32/32. The
 * runtime behaviour is load-bearing; what was wrong was the claim that the gate
 * measured it. So the fix is a coverage dimension, and these tests keep it
 * honest — every assertion below is proved through the REAL engine, not against
 * a hand-written expectation of what the engine does.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import {
  skillPathBlocker,
  skillPathCoverage,
  SKILL_NATIVE_SCAN_TARGETS,
  type RuleLike,
  type SkillPathGap,
} from "../scripts/lib/corpus-event.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Counts on main at 70bd9cabb, re-derived by this file from the rules on disk.
 * They are a RATCHET, not a specification: the corpus grows daily, so the
 * assertions below are bounds and invariants, and this block exists so a reader
 * can tell whether a change moved the number and by how much.
 */
const MEASURED_ON_MAIN = Object.freeze({
  rules: 780,
  skillPathUnreachable: 645,
  unreachableInEnforceLane: 102,
  reachable: 128,
  inertStatus: 7,
});

let cachedEngine: ATREngine | null = null;
async function engine(): Promise<ATREngine> {
  if (cachedEngine === null) {
    const e = new ATREngine({ rulesDir: join(REPO_ROOT, "rules") });
    await e.loadRules();
    cachedEngine = e;
  }
  return cachedEngine;
}

/** Flatten a test-case object into the most favourable single SKILL.md body. */
function flattenTestCase(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.map(flattenTestCase).join("\n");
  if (typeof v === "object") {
    return Object.values(v as Record<string, unknown>).map(flattenTestCase).join("\n");
  }
  return String(v);
}

/**
 * Best-case skill documents for a rule: its OWN declared true positives, every
 * field value poured into one body. In skill context resolveField() returns
 * event.content for every field name, so this is the most generous input the
 * rule can possibly receive on that path. If it still cannot fire, nothing can
 * make it fire.
 */
function ownTruePositiveDocuments(
  rule: { test_cases?: { true_positives?: unknown[] } },
  limit = Number.POSITIVE_INFINITY,
): string[] {
  const out: string[] = [];
  for (const tp of rule.test_cases?.true_positives ?? []) {
    if (out.length >= limit) break;
    const text = flattenTestCase(tp);
    if (text.trim() !== "") out.push(text);
  }
  return out;
}

function corpusFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...corpusFiles(full));
    else if (full.endsWith(".md")) out.push(full);
  }
  return out.sort();
}

/**
 * scanSkill() over a whole SKILL.md is expensive with 780 rules loaded, so the
 * full 498-file benchmark is a multi-minute test on its own. These suites take
 * every malicious sample and a deterministic stride through the benign ones —
 * enough to catch a predicate that has drifted, cheap enough to run per PR. The
 * exhaustive sweep (all 466 benign, all true positives of all 780 rules, 4507
 * documents) was run once by hand on this branch and agreed with the predicate
 * on every rule; these bounds keep it that way without paying for it each time.
 */
const BENIGN_STRIDE = 4;
const MAX_TP_DOCS_PER_RULE = 2;

/** Malicious samples are all swept; benign are strided. Fixed at collection. */
const SWEPT_CORPUS_FILES: readonly string[] = Object.freeze([
  ...corpusFiles(join(REPO_ROOT, "data/skill-benchmark/malicious")),
  ...corpusFiles(join(REPO_ROOT, "data/skill-benchmark/benign")).filter(
    (_, i) => i % BENIGN_STRIDE === 0,
  ),
]);

/** Rule files on disk, counted rather than remembered. */
function ruleFileCount(dir = join(REPO_ROOT, "rules")): number {
  let n = 0;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) n += ruleFileCount(full);
    else if (full.endsWith(".yaml")) n += 1;
  }
  return n;
}

/**
 * DEADLINE FOR A scanSkill() SWEEP — derived, not chosen.
 *
 * This test first shipped with a flat `170_000`. On CI it needed 221,525ms and
 * was reported as a failure, which is the worst possible way for it to fail:
 * the assertion inside it had in fact been satisfied (re-run by hand on the FULL
 * 498-file corpus, not just the strided 149: zero rules called unreachable
 * fired), so a green predicate was showing up in the log as a red ratchet. A
 * flat millisecond deadline over work that grows with both the corpus and the
 * rule set measures the runner, which is the defect #418 removed from
 * tests/eval-harness.test.ts and tests/skill-benchmark.test.ts.
 *
 * So the deadline is expressed in the SAME unit its sibling already uses. The
 * catastrophe ceiling in tests/skill-benchmark.test.ts is 3.0ms per rule per
 * sample over this identical corpus and this identical scanSkill() call —
 * ~9.5x the quiet reading that test records, and the number #418 derived. This
 * sweep scans a known number of samples against a known number of rules, so its
 * deadline is that ceiling times the work assigned to it, and rule growth (the
 * point of the project) can never walk into it.
 *
 * WHAT IT STILL CATCHES. It is a catastrophe deadline, deliberately. Readings
 * of THIS test, 780 rules, 149 strided samples:
 *   - CI, before the duplicate-regex fix in src/engine.ts : 1.906 ms/rule/sample
 *     (221,525ms — run 30997081920, the one that produced the false red)
 *   - CI, after it                                        : 1.004
 *     (116,653ms — run 31004061103, green)
 *   - this box, quiet, after it                           : 0.172
 *     (19,969ms, in the full-suite run that verified this commit)
 * So 3.0 is 1.57x the worst reading ever taken here, 2.99x what the CI runner
 * now produces, and 17.4x a quiet box. Removing the `if (isAny) break;`
 * short-circuit, the change these tests exist to catch, takes the benign corpus
 * from 1 flagged sample to 265 and multiplies the matching work far past that.
 *
 * Sanity check on the absolute size: tests/skill-benchmark.test.ts already gives
 * its beforeAll 600,000ms on CI to sweep all 498 samples the same way. This
 * deadline is smaller than that for a smaller sweep.
 */
const CATASTROPHE_MS_PER_RULE_PER_SAMPLE = 3.0;
const CORPUS_SWEEP_TIMEOUT_MS = Math.ceil(
  SWEPT_CORPUS_FILES.length * ruleFileCount() * CATASTROPHE_MS_PER_RULE_PER_SAMPLE,
);

describe("skillPathCoverage — the skill half of matchedRuleIds asks almost nothing", () => {
  it("reports a gap for every rule that cannot match on the skill path, and none for the rest", async () => {
    const e = await engine();
    const rules = e.getRules() as unknown as RuleLike[];
    const gaps = skillPathCoverage(rules);
    const gapIds = new Set(gaps.map((g) => g.ruleId));

    expect(rules.length).toBeGreaterThanOrEqual(MEASURED_ON_MAIN.rules);
    expect(gaps.length).toBeGreaterThan(0);
    // Every rule is in exactly one bucket: gap, inert status, or reachable.
    const inert = rules.filter((r) => r.status === "draft" || r.status === "deprecated");
    for (const r of inert) {
      expect(gapIds.has(r.id), `${r.id} is inert — statusCoverage owns it, not this axis`).toBe(
        false,
      );
    }
  });

  it(
    "NO rule it calls unreachable can be made to fire on the skill path by its own true positives",
    async () => {
      const e = await engine();
      const rules = e.getRules() as unknown as (RuleLike & {
        test_cases?: { true_positives?: unknown[] };
      })[];
      const gapIds = new Set(skillPathCoverage(rules).map((g) => g.ruleId));

      const falsified: string[] = [];
      for (const rule of rules) {
        if (!gapIds.has(rule.id)) continue;
        for (const doc of ownTruePositiveDocuments(rule, MAX_TP_DOCS_PER_RULE)) {
          if (e.scanSkill(doc).some((m) => m.rule.id === rule.id)) {
            falsified.push(rule.id);
            break;
          }
        }
      }
      expect(
        falsified,
        "these rules were reported as structurally unable to fire on engine.scanSkill(), " +
          "but they fired on their own declared attack samples. skillPathBlocker() no longer " +
          "mirrors src/engine.ts — fix the predicate before trusting any coverage report.",
      ).toEqual([]);
    },
    170_000,
  );

  it(
    "the benign and malicious skill corpora trip ONLY rules it calls reachable",
    async () => {
      const e = await engine();
      const gapIds = new Set(
        skillPathCoverage(e.getRules() as unknown as RuleLike[]).map((g) => g.ruleId),
      );
      const benign = corpusFiles(join(REPO_ROOT, "data/skill-benchmark/benign"));
      const malicious = corpusFiles(join(REPO_ROOT, "data/skill-benchmark/malicious"));
      expect(benign.length + malicious.length).toBeGreaterThan(400);
      // Same list the deadline was derived from, so the budget and the work
      // cannot drift apart.
      const files = SWEPT_CORPUS_FILES;
      expect(files.length).toBe(malicious.length + Math.ceil(benign.length / BENIGN_STRIDE));

      const fired = new Set<string>();
      for (const file of files) {
        for (const m of e.scanSkill(readFileSync(file, "utf-8"))) fired.add(m.rule.id);
      }
      expect(fired.size).toBeGreaterThan(0);
      expect(
        [...fired].filter((id) => gapIds.has(id)),
        "a rule reported as unreachable on the skill path fired on the skill benchmark",
      ).toEqual([]);
    },
    CORPUS_SWEEP_TIMEOUT_MS,
  );

  it("names the enforce-lane rules the skill path never asks about", async () => {
    const e = await engine();
    const gaps = skillPathCoverage(e.getRules() as unknown as RuleLike[]);
    const enforce = gaps.filter((g) => g.claimsEnforceLane);
    // Not zero, and that is the finding. Every one of them is measured on the
    // evaluate() shapes; none of them is measured on the skill shape.
    expect(enforce.length).toBeGreaterThan(0);
    for (const g of enforce) {
      expect(g.maturity).toBe("stable");
      expect(g.reason).not.toBe("");
    }
  });

  it("every enforce-lane rule the skill path cannot reach IS measurable on the evaluate() shapes", async () => {
    const e = await engine();
    const rules = e.getRules() as unknown as (RuleLike & {
      maturity?: string;
      test_cases?: { true_positives?: unknown[] };
    })[];
    const gapIds = new Set(skillPathCoverage(rules).map((g) => g.ruleId));

    const { corpusShapes } = await import("../scripts/lib/corpus-event.js");
    const blindEverywhere: string[] = [];
    for (const rule of rules) {
      if (rule.maturity !== "stable" || !gapIds.has(rule.id)) continue;
      const docs = ownTruePositiveDocuments(rule, MAX_TP_DOCS_PER_RULE);
      if (docs.length === 0) continue;
      const firesSomewhere = docs.some((doc) =>
        corpusShapes(doc).some((s) => e.evaluate(s.event).some((m) => m.rule.id === rule.id)),
      );
      if (!firesSomewhere) blindEverywhere.push(rule.id);
    }
    expect(
      blindEverywhere,
      "these enforce-lane rules cannot fire on the skill path AND cannot fire on any " +
        "evaluate() shape with their own attack samples — their 0 FP is a zero measurement " +
        "on every path the gate has, which is a promotion that must not stand",
    ).toEqual([]);
  }, 170_000);
});

describe("the predicate mirrors src/engine.ts rather than restating it", () => {
  const engineSource = (): string => readFileSync(join(REPO_ROOT, "src/engine.ts"), "utf-8");

  it("the skill compound gate still exempts exactly scan_target skill and both", () => {
    const src = engineSource();
    const occurrences = [
      ...src.matchAll(
        /isSkillContext\s*&&\s*rule\.tags\.scan_target\s*!==\s*'([a-z]+)'\s*&&\s*rule\.tags\.scan_target\s*!==\s*'([a-z]+)'/g,
      ),
    ];
    expect(
      occurrences.length,
      "the skill compound gate moved or changed shape — re-derive skillPathBlocker()",
    ).toBe(2); // evaluateRaw + evaluateAsync
    for (const m of occurrences) {
      expect(new Set([m[1] as string, m[2] as string])).toEqual(SKILL_NATIVE_SCAN_TARGETS);
    }
  });

  it("the compound gate still demands max(2, ceil(0.3 * conditions))", () => {
    const src = engineSource();
    expect(src).toContain("Math.max(2, Math.ceil(totalConds * 0.3))");
    expect(src).toContain("Number(rule.detection?.conditions?.length ?? 1)");
  });

  it("evaluateArrayConditions still short-circuits, which is what caps matchedConditions at 1", () => {
    const src = engineSource();
    const start = src.indexOf("private evaluateArrayConditions(");
    expect(start).toBeGreaterThan(0);
    const body = src.slice(start, src.indexOf("\n  }", start));
    expect(
      /if\s*\(isAny\)\s*break;/.test(body),
      "the any-mode short-circuit is gone. matchedConditions can now exceed 1, so the " +
        "skill compound gate has become reachable and rules that were structurally silent " +
        "on SKILL.md will start firing. Re-measure the benign skill corpus before shipping.",
    ).toBe(true);
  });
});

describe("skillPathBlocker — the individual mechanisms", () => {
  const base = (over: Partial<RuleLike> = {}): RuleLike => ({
    id: "ATR-2026-90001",
    status: "experimental",
    maturity: "test",
    tags: { scan_target: "mcp" },
    detection: {
      condition: "any",
      conditions: [{ field: "content", operator: "regex", value: "x" }],
    },
    ...over,
  });

  const blockerOf = (rule: RuleLike): SkillPathGap | null => skillPathBlocker(rule);

  it("an any-mode rule is unreachable no matter how many conditions it declares", () => {
    for (const n of [1, 2, 5, 13]) {
      const rule = base({
        detection: {
          condition: "any",
          conditions: Array.from({ length: n }, () => ({ field: "content", operator: "regex", value: "x" })),
        },
      });
      const gap = blockerOf(rule);
      expect(gap?.blocker, `${n} conditions`).toBe("compound-gate-unreachable");
      expect(gap?.maxAttainableConditions).toBe(1);
      expect(gap?.requiredConditions).toBeGreaterThanOrEqual(2);
    }
  });

  it("an all-mode rule with 2+ conditions is reachable", () => {
    const rule = base({
      detection: {
        condition: "all",
        conditions: [
          { field: "content", operator: "regex", value: "x" },
          { field: "content", operator: "regex", value: "y" },
        ],
      },
    });
    expect(blockerOf(rule)).toBeNull();
  });

  it("an all-mode rule with one condition is unreachable — it can never report 2", () => {
    const rule = base({
      detection: {
        condition: "all",
        conditions: [{ field: "content", operator: "regex", value: "x" }],
      },
    });
    expect(blockerOf(rule)?.blocker).toBe("compound-gate-unreachable");
  });

  it.each([...SKILL_NATIVE_SCAN_TARGETS])("scan_target %s is exempt from the gate", (target) => {
    expect(blockerOf(base({ tags: { scan_target: target } }))).toBeNull();
  });

  it.each([
    ["trace", "method-trace"],
    ["behavioral", "method-behavioral"],
    ["signature", "method-signature"],
  ])("method %s is unreachable on the skill path even with scan_target: skill", (method, blocker) => {
    const rule = base({
      tags: { scan_target: "skill" },
      detection: { method, condition: "any", conditions: [{ field: "content" }] },
    });
    expect(blockerOf(rule)?.blocker).toBe(blocker);
  });

  it("a semantic rule is unreachable unless it falls back to pattern", () => {
    const noFallback = base({
      tags: { scan_target: "skill" },
      detection: { method: "semantic", condition: "any", conditions: [{ field: "content" }] },
    });
    expect(blockerOf(noFallback)?.blocker).toBe("method-semantic-no-pattern-fallback");

    const withFallback = base({
      tags: { scan_target: "skill" },
      detection: {
        method: "semantic",
        semantic: { fallback_method: "pattern" },
        condition: "any",
        conditions: [{ field: "content" }],
      },
    });
    expect(blockerOf(withFallback)).toBeNull();
  });

  it("a named-map with a single condition is unreachable (conditions.length is undefined -> 1)", () => {
    const rule = base({
      detection: {
        condition: "only_one",
        conditions: { only_one: { field: "content", patterns: ["x"] } },
      },
    });
    const gap = blockerOf(rule);
    expect(gap?.blocker).toBe("compound-gate-unreachable");
    expect(gap?.maxAttainableConditions).toBe(1);
    expect(gap?.requiredConditions).toBe(2);
  });

  it("an inert rule is left to statusCoverage rather than double-reported", () => {
    expect(blockerOf(base({ status: "draft" }))).toBeNull();
    expect(blockerOf(base({ status: "deprecated" }))).toBeNull();
  });

  it("records the numbers measured on main so a change is visible, not silent", async () => {
    const e = await engine();
    const rules = e.getRules() as unknown as RuleLike[];
    const gaps = skillPathCoverage(rules);
    // Bounds, not equalities: the corpus grows. A DROP means the skill path just
    // started evaluating rules it never did — that is a detection-behaviour
    // change and must be deliberate.
    expect(
      gaps.length,
      `skill-path-unreachable count fell below the ${MEASURED_ON_MAIN.skillPathUnreachable} ` +
        `measured on main@70bd9cabb. If that was intended, re-run the benign skill corpus ` +
        `(466 samples, 1 flagged before) and update this ratchet with the new number.`,
    ).toBeGreaterThanOrEqual(MEASURED_ON_MAIN.skillPathUnreachable);
    expect(gaps.filter((g) => g.claimsEnforceLane).length).toBeGreaterThanOrEqual(
      MEASURED_ON_MAIN.unreachableInEnforceLane,
    );
  });
});
