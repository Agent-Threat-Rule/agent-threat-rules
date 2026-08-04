/**
 * Tests for the per-rule regex cost ratchet -- the parts that touch something
 * real: the engine, the committed baseline, and the CLI entry point.
 *
 * The metric and its verdicts are exercised synthetically in
 * tests/gate-rule-latency.test.ts. What is here cannot be: a gate whose
 * measurement layer is only ever fed synthetic numbers is a gate that can
 * silently stop measuring, and a CLI whose "invoked directly" guard breaks is a
 * silent no-op. So this file profiles a real fixture corpus containing a real
 * backtracking regex, and drives the real committed baseline through the real
 * process boundary.
 *
 * It also pins the anti-muting properties, which are the ones an author under
 * deadline pressure would reach for: shrinking the eval corpus, culling the
 * cohort the denominator is made of, or handing the gate a baseline shaped just
 * wrong enough to read as empty.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  anchorCoverage,
  anchorsEroded,
  relativeCosts,
  corpusShrank,
  renderGate,
  parseBaseline,
  baselineFrom,
  buildProfile,
  isEvaluable,
  isCorpusCovered,
  EMPTY_BASELINE,
  FAIL_FLOOR,
  ANCHOR_MIN_COVERAGE,
  type Profile,
  type Baseline,
} from "../scripts/gate-rule-latency.js";
import type { ATRRule } from "../src/types.js";
import { MEDIAN_MS, baselineOf, fixtureRule, makeProfile, report, verdict, withoutRules } from "./rule-latency-fixtures.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(REPO_ROOT, "scripts/gate-rule-latency.ts");
const COMMITTED_BASELINE_PATH = join(REPO_ROOT, "data/rule-latency-baseline.json");

// ---------------------------------------------------------------------------
// 7. Anti-muting
// ---------------------------------------------------------------------------

describe("cannot be quietly muted", () => {
  const base = baselineOf(makeProfile({ "ATR-EXP-1": 12 }));

  it("a shrunken eval corpus is a broken gate (exit 2), not a passing one", () => {
    // Deleting the sample that triggers a pathological regex is the cheapest way
    // to make it disappear. Exit 0 would reward that.
    const shrunk: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), samples: 200 };
    expect(corpusShrank(shrunk, base)).toContain("shrank");
    expect(verdict(shrunk, base)).toBe(2);
  });

  it("a grown eval corpus is fine", () => {
    const grown: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), samples: 400 };
    expect(corpusShrank(grown, base)).toBeNull();
    expect(verdict(grown, base)).toBe(0);
  });

  it("a culled anchor cohort is a broken gate (exit 2), not a cheaper corpus", () => {
    // The other axis of the same attack: the denominator is a median over named
    // rules, so deleting or drafting enough of them moves every relCost with no
    // regex having changed.
    const profile = makeProfile({ "ATR-EXP-1": 12 }, 400);
    const wide = baselineOf(profile);
    const culled = withoutRules(
      profile,
      Object.keys(profile.costs).filter((id) => id.startsWith("ATR-ORD-")).slice(0, 200)
    );
    expect(anchorCoverage(culled, wide).fraction).toBeLessThan(ANCHOR_MIN_COVERAGE);
    expect(anchorsEroded(culled, wide)).toContain("anchor rules");
    expect(verdict(culled, wide)).toBe(2);
  });

  it("rejects a baseline whose expensiveRules is an array", () => {
    // gate-re2-portability.ts learned this one: an array passes a bare typeof
    // check, reads as an empty baseline, and turns the whole corpus into
    // "new regressions" -- or, with the failure floor, into a silent pass.
    expect(() => parseBaseline({ expensiveRules: [], latencyShape: 1.9, corpus: { samples: 341 } }, "x")).toThrow(
      /must be an object/
    );
  });

  it.each([
    [{ expensiveRules: { "ATR-1": "12" }, latencyShape: 1.9, corpus: { samples: 341 } }, /positive number/],
    [{ expensiveRules: { "ATR-1": -3 }, latencyShape: 1.9, corpus: { samples: 341 } }, /positive number/],
    [{ expensiveRules: {}, latencyShape: 0, corpus: { samples: 341 } }, /latencyShape/],
    [{ expensiveRules: {}, latencyShape: 1.9, corpus: {} }, /corpus.samples/],
    [
      { expensiveRules: {}, latencyShape: 1.9, corpus: { samples: 341 }, anchorRuleIds: {} },
      /anchorRuleIds/,
    ],
  ])("rejects a malformed baseline (%#)", (doc, pattern) => {
    expect(() => parseBaseline(doc, "x")).toThrow(pattern);
  });

  it("keeps the skipped-rule list so an un-skipped rule cannot inherit a pass", () => {
    const profile: Profile = { ...makeProfile({ "ATR-EXP-1": 12 }), skippedRuleIds: ["ATR-DRAFT-1"] };
    const written = baselineOf(profile);
    expect(written.skippedRuleIds).toContain("ATR-DRAFT-1");
    // It is not in expensiveRules, so flipping it back to active makes it a
    // not-in-baseline rule and it gets judged on its own merits.
    expect(written.expensiveRules).not.toHaveProperty("ATR-DRAFT-1");
  });

  it("warns when a new rule hides in an event type the corpus never emits", () => {
    // The measured blind spot: the same backtracking regex declared agent_trace
    // instead of llm_io ranks 670th of 671 because the engine skips it. Silence
    // would make that a discovery; a warning makes it a decision.
    const profile: Profile = {
      ...makeProfile({ "ATR-EXP-1": 12 }),
      unprofilableRuleIds: ["ATR-2026-00070", "ATR-2026-99999"],
    };
    const known: Baseline = { ...base, unprofilableRuleIds: ["ATR-2026-00070"] };
    const text = report(profile, known);
    expect(text).toContain("ATR-2026-99999");
    expect(text).not.toContain("? ATR-2026-00070");
    expect(verdict(profile, known)).toBe(0);
  });

  it("warns when rule files failed to parse or the tree was dirty mid-profile", () => {
    const profile: Profile = {
      ...makeProfile({ "ATR-EXP-1": 12 }),
      unparsedFiles: 3,
      dirtyRulePaths: ["?? rules/prompt-injection/ATR-2026-99668.yaml"],
    };
    const text = report(profile, base);
    expect(text).toContain("3 rule file(s) failed to parse");
    expect(text).toContain("uncommitted path(s) under rules/");
  });
});

// ---------------------------------------------------------------------------
// 8. Engine agreement -- what the profiler skips must match what the engine skips
// ---------------------------------------------------------------------------

describe("evaluability mirrors the engine", () => {
  const rule = (over: Partial<ATRRule>): ATRRule => ({ status: "experimental", maturity: "test", ...over }) as ATRRule;

  it.each([
    ["draft", false],
    ["deprecated", false],
    ["experimental", true],
    ["active", true],
  ])("status %s -> evaluable %s", (status, expected) => {
    expect(isEvaluable(rule({ status: status as ATRRule["status"] }))).toBe(expected);
  });

  it("skips maturity=deprecated, which the engine drops in every lane", () => {
    expect(isEvaluable(rule({ maturity: "deprecated" }))).toBe(false);
    expect(isEvaluable(rule({ maturity: "stable" }))).toBe(true);
  });

  it.each([
    ["llm_io", true],
    ["tool_call", true],
    ["mcp_exchange", true],
    ["multi_agent_comm", true],
    ["memory_access", false],
    ["context_window", false],
    ["skill_lifecycle", false],
  ])("source type %s -> exercised by the eval corpus: %s", (type, expected) => {
    expect(isCorpusCovered(rule({ agent_source: { type } } as Partial<ATRRule>))).toBe(expected);
  });

  it("treats a trace-method rule as unexercised whatever its source type says", () => {
    // sampleToEvent never sets event.trace, so the engine's traceWithPayload
    // branch cannot fire and the rule's primitives never run.
    expect(
      isCorpusCovered(rule({ agent_source: { type: "llm_io" }, detection: { method: "trace" } } as Partial<ATRRule>))
    ).toBe(false);
  });
});


describe("end to end over a fixture corpus", () => {
  it(
    "really measures a backtracking regex and names it",
    { timeout: 240_000 },
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "atr-latency-fixture-"));
      mkdirSync(join(dir, "prompt-injection"), { recursive: true });
      const write = (id: string, pattern: string, type?: string): void =>
        writeFileSync(join(dir, "prompt-injection", `${id}.yaml`), fixtureRule(id, pattern, type));

      try {
        // Five ordinary rules so the median is a real median, plus one whose
        // bounded outer quantifier wraps an unbounded inner one.
        write("ATR-2026-90001", "ignore\\s+previous\\s+instructions");
        write("ATR-2026-90002", "system\\s+prompt");
        write("ATR-2026-90003", "developer\\s+mode");
        write("ATR-2026-90004", "reveal\\s+your\\s+rules");
        write("ATR-2026-90005", "act\\s+as\\s+DAN");
        write("ATR-2026-90666", "^(?:[a-z]+\\s*){0,6}ZQXKFJ$");

        const profile = await buildProfile(dir);
        expect(profile.rules).toBe(6);
        expect(profile.samples).toBeGreaterThan(300);

        const costs = relativeCosts(profile);
        expect(costs[0]!.ruleId).toBe("ATR-2026-90666");
        // Measured at 50x-72x the median of these five trivial rules. Assert only
        // the floor the gate actually uses, so this does not quietly become a
        // machine-speed test.
        expect(costs[0]!.rel).toBeGreaterThan(FAIL_FLOOR);

        const result = renderGate(profile, costs, EMPTY_BASELINE);
        expect(result.exitCode).toBe(1);
        expect(result.lines.join("\n")).toContain("ATR-2026-90666");

        // ...and once accepted into a baseline, the same measurement passes.
        const accepted = baselineFrom(profile, costs);
        expect(verdict(profile, accepted)).toBe(0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  );

  it("excludes rules this corpus cannot exercise instead of scoring them", { timeout: 240_000 }, async () => {
    // The honest half of the blind spot: the same pathological regex declared
    // under a source type the corpus never emits profiles at dispatch cost. It
    // must not enter the denominator as a fake cheap rule.
    const dir = mkdtempSync(join(tmpdir(), "atr-latency-uncovered-"));
    mkdirSync(join(dir, "prompt-injection"), { recursive: true });
    try {
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90201.yaml"),
        fixtureRule("ATR-2026-90201", "ignore\\s+previous")
      );
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90202.yaml"),
        fixtureRule("ATR-2026-90202", "^(?:[a-z]+\\s*){0,6}ZQXKFJ$", "memory_access")
      );

      const profile = await buildProfile(dir);
      expect(Object.keys(profile.costs)).toEqual(["ATR-2026-90201"]);
      expect(profile.unprofilableRuleIds).toEqual(["ATR-2026-90202"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("skips draft and deprecated rules the engine would never evaluate", { timeout: 240_000 }, async () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-latency-skip-"));
    mkdirSync(join(dir, "prompt-injection"), { recursive: true });
    try {
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90101.yaml"),
        fixtureRule("ATR-2026-90101", "ignore\\s+previous")
      );
      writeFileSync(
        join(dir, "prompt-injection", "ATR-2026-90102.yaml"),
        fixtureRule("ATR-2026-90102", "system\\s+prompt").replace("status: experimental", "status: draft")
      );

      const profile = await buildProfile(dir);
      expect(Object.keys(profile.costs)).toEqual(["ATR-2026-90101"]);
      expect(profile.skippedRuleIds).toEqual(["ATR-2026-90102"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 10. The committed baseline, and the CLI entry point
// ---------------------------------------------------------------------------

describe("committed baseline", () => {
  const committed = parseBaseline(JSON.parse(readFileSync(COMMITTED_BASELINE_PATH, "utf8")), COMMITTED_BASELINE_PATH);

  /**
   * A synthetic profile whose membership is the committed anchor cohort, so the
   * CLI tests exercise the real baseline rather than a fixture. Costs are read
   * back out of the baseline itself, which keeps the fixture in step when the
   * baseline is regenerated -- the previous version hard-coded samples: 341 and
   * would have started returning exit 2 (corpus shrank) the day the eval corpus
   * grew and the baseline was refreshed.
   */
  function profileFromCommitted(extra: Record<string, number> = {}): Profile {
    const costs: Record<string, { ms: number; file: string }> = {};
    for (const id of committed.anchorRuleIds) {
      costs[id] = { ms: MEDIAN_MS * (committed.expensiveRules[id] ?? 1), file: `rules/committed/${id}.yaml` };
    }
    for (const [id, rel] of Object.entries(extra)) {
      costs[id] = { ms: MEDIAN_MS * rel, file: `rules/synthetic/${id}.yaml` };
    }
    return {
      ...makeProfile({}, 3, 1, committed.corpus.samples),
      rules: Object.keys(costs).length,
      costs,
      latencyShape: committed.latencyShape,
    };
  }

  it("records a cohort, a corpus and a shape that the gate can actually use", () => {
    expect(committed.anchorRuleIds.length).toBeGreaterThan(100);
    expect(committed.corpus.samples).toBeGreaterThan(300);
    expect(committed.latencyShape).toBeGreaterThan(1);
    expect(Object.keys(committed.expensiveRules).length).toBeGreaterThan(0);
    // Every recorded expensive rule is in the cohort it was measured against.
    for (const id of Object.keys(committed.expensiveRules)) {
      expect(committed.anchorRuleIds).toContain(id);
    }
  });

  it("passes the rules it recorded, at the costs it recorded", () => {
    expect(verdict(profileFromCommitted(), committed)).toBe(0);
  });

  it("still fails a pathological newcomer against the committed cohort", () => {
    expect(verdict(profileFromCommitted({ "ATR-SYN-500": 500 }), committed)).toBe(1);
  });
});

describe("CLI", () => {
  const committed = parseBaseline(JSON.parse(readFileSync(COMMITTED_BASELINE_PATH, "utf8")), COMMITTED_BASELINE_PATH);

  function runCli(args: readonly string[]): { status: number; out: string } {
    const result = spawnSync("npx", ["tsx", SCRIPT, ...args], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 240_000,
    });
    return { status: result.status ?? -1, out: `${result.stdout ?? ""}${result.stderr ?? ""}` };
  }

  function writeProfileFixture(profile: Profile): string {
    const dir = mkdtempSync(join(tmpdir(), "atr-latency-cli-"));
    const path = join(dir, "profile.json");
    writeFileSync(path, JSON.stringify(profile, null, 2));
    return path;
  }

  it("exits 1 and names the rule when a profile regresses", { timeout: 240_000 }, () => {
    const costs: Record<string, { ms: number; file: string }> = {};
    for (const id of committed.anchorRuleIds) {
      costs[id] = { ms: MEDIAN_MS * (committed.expensiveRules[id] ?? 1), file: `rules/committed/${id}.yaml` };
    }
    costs["ATR-SYN-500"] = { ms: MEDIAN_MS * 500, file: "rules/synthetic/ATR-SYN-500.yaml" };
    const profile: Profile = {
      ...makeProfile({}, 3, 1, committed.corpus.samples),
      rules: Object.keys(costs).length,
      costs,
      latencyShape: committed.latencyShape,
    };

    const { status, out } = runCli(["--profile", writeProfileFixture(profile)]);
    expect(status).toBe(1);
    expect(out).toContain("ATR-SYN-500");
    expect(out).toContain("Do NOT widen the baseline to silence this.");
  });

  it("exits 2 when it cannot run", { timeout: 240_000 }, () => {
    const { status, out } = runCli(["--profile", "/nonexistent/profile.json"]);
    expect(status).toBe(2);
    expect(out).toContain("could not run");
  });

  it("exits 2 on a flag missing its argument rather than silently ignoring it", { timeout: 240_000 }, () => {
    const { status } = runCli(["--profile"]);
    expect(status).toBe(2);
  });
});

