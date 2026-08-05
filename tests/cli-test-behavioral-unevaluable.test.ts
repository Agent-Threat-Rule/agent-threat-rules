/**
 * Tests for how `atr test` reports method=behavioral rules.
 *
 * THE BUG THIS PINS
 *   engine.ts returns null for method=behavioral without evaluating anything —
 *   deliberately, because windowed metric evaluation needs state across many
 *   events and the synchronous evaluate() API carries none. The test runner
 *   did not know that, so it ran every case anyway and reported each
 *   true_positive as "Expected: triggered, Got: not_triggered".
 *
 *   That reads as a detection failure. The truth is that the engine never
 *   looked. ATR-2026-00553 — the corpus's only behavioral rule, and the
 *   reference example shipped with v1.1 of the method-extensions spec — had
 *   five such "failures" sitting on main. Nobody saw them because
 *   rule-quality.yml only tests files a PR changes, so the breakage stayed
 *   dormant until someone edited that file for an unrelated reason.
 *
 *   Cases the engine cannot evaluate are now counted and named as
 *   unevaluable. Not failed, which blames the rule for the harness's gap, and
 *   not quietly passed, which would hide that nothing ran.
 *
 * The CLI is spawned rather than imported because cmdTest is not exported, and
 * the contract worth pinning is what an operator and CI actually see on
 * stdout — the counts and the exit code — not an internal function's return.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const CLI = new URL("../src/cli.ts", import.meta.url).pathname;

/** A rule that differs from the pattern case only in detection.method. */
function ruleYaml(method: "behavioral" | "pattern"): string {
  return `title: "Fixture"
id: ATR-2026-09001
rule_version: 1
status: experimental
description: "Fixture rule for harness reporting."
author: "ATR Community"
date: "2026/08/05"
schema_version: "0.1"
maturity: test
severity: low
tags:
  category: excessive-autonomy
  subcategory: fixture
  scan_target: both
  confidence: low
agent_source:
  type: agent_behavior
  framework: [any]
  provider: [any]
detection:
  method: ${method}
  condition: any
  conditions:
    - field: content
      operator: regex
      value: "(?i)threshold_exceeded_marker"
      description: "fixture"
${method === "behavioral" ? `  behavioral:
    metric: "tool_calls"
    aggregation: count
    window: "PT1M"
    operator: gt
    threshold: 100
` : ""}response:
  actions: [alert]
  message_template: "fixture"
test_cases:
  true_positives:
    - input: "threshold_exceeded_marker"
      expected: triggered
  true_negatives:
    - input: "nothing to see"
      expected: not_triggered
`;
}

interface TestReport {
  totalTests: number;
  passed: number;
  failed: number;
  skipped: number;
  skippedRules: Array<{ ruleId: string; cases: number; reason: string }>;
}

function runCli(method: "behavioral" | "pattern"): { report: TestReport; status: number } {
  const dir = mkdtempSync(join(tmpdir(), "atr-harness-"));
  try {
    const rulesDir = join(dir, "rules", "excessive-autonomy");
    mkdirSync(rulesDir, { recursive: true });
    const file = join(rulesDir, "ATR-2026-09001-fixture.yaml");
    writeFileSync(file, ruleYaml(method));

    const r = spawnSync("npx", ["tsx", CLI, "test", file, "--json"], {
      encoding: "utf8",
      timeout: 120_000,
    });
    const stdout = r.stdout ?? "";
    const start = stdout.indexOf("{");
    expect(start, `no JSON in stdout: ${stdout}${r.stderr}`).toBeGreaterThanOrEqual(0);
    return { report: JSON.parse(stdout.slice(start)) as TestReport, status: r.status ?? -1 };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("atr test — method=behavioral reporting", () => {
  it("counts behavioral cases as unevaluable rather than failed", () => {
    const { report, status } = runCli("behavioral");

    // The engine never evaluated them, so calling them failures blames the rule.
    expect(report.failed).toBe(0);
    // And calling them passes would hide that nothing ran.
    expect(report.passed).toBe(0);
    expect(report.skipped).toBe(2);
    expect(report.totalTests).toBe(2);
    expect(status).toBe(0);
  });

  it("names the rule and the reason, so a skip is never silent", () => {
    const { report } = runCli("behavioral");

    expect(report.skippedRules).toHaveLength(1);
    expect(report.skippedRules[0]?.ruleId).toBe("ATR-2026-09001");
    expect(report.skippedRules[0]?.cases).toBe(2);
    expect(report.skippedRules[0]?.reason).toMatch(/behavioral/i);
  });

  it("still evaluates an otherwise identical pattern rule", () => {
    // Guards against the skip widening past method=behavioral: the same
    // conditions, source type and cases must run normally under method=pattern.
    const { report, status } = runCli("pattern");

    expect(report.skipped).toBe(0);
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(2);
    expect(status).toBe(0);
  });
});
