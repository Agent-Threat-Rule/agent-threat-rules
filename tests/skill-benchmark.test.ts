/**
 * SKILL.md Benchmark Test Suite
 *
 * Runs the full SKILL.md benchmark corpus and validates:
 * - Overall recall >= 90% (regression gate — raised after real-world corpus upgrade)
 * - Overall precision >= 95% (regression gate)
 * - FP rate <= 0.5% (regression gate — tightened with 466 real-world benign)
 * - Layer A recall >= 95% (obvious payloads)
 * - Layer C recall >= 80% (semantic/evasive — regex ceiling)
 * - Zero false positives on official MCP server READMEs
 * - Per-sample latency inside a catastrophe ceiling that scales with the rule
 *   count (absolute millisecond budgets measured the machine, not the rules —
 *   see the derivation on the assertion itself)
 *
 * The benchmark is run once in `beforeAll` and shared across assertions so the
 * suite finishes in one scan instead of eight.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { runSkillBenchmark } from '../src/eval/skill-benchmark.js';

type BenchmarkReport = Awaited<ReturnType<typeof runSkillBenchmark>>;

describe('SKILL.md Benchmark', () => {
  let report: BenchmarkReport;

  beforeAll(async () => {
    report = await runSkillBenchmark();
    // Setup runs the full corpus x rule-set once. Local finishes in seconds,
    // but shared CI runners are slow and variable — give generous headroom so
    // a loaded runner doesn't flake the whole release on a setup timeout.
  }, process.env.CI ? 600_000 : 180_000);

  it('meets recall threshold (>= 90%)', () => {
    expect(report.overall_recall).toBeGreaterThanOrEqual(0.9);
  });

  it('meets precision threshold (>= 95%)', () => {
    expect(report.overall_precision).toBeGreaterThanOrEqual(0.95);
  });

  it('FP rate <= 0.5%', () => {
    expect(report.fp_rate).toBeLessThanOrEqual(0.005);
  });

  it('Layer A recall >= 95% (obvious payloads)', () => {
    expect(report.layer_a.recall).toBeGreaterThanOrEqual(0.95);
  });

  it('Layer C recall >= 80% (semantic/evasive)', () => {
    expect(report.layer_c.recall).toBeGreaterThanOrEqual(0.8);
  });

  it('zero FP on official MCP server READMEs', () => {
    const mcpFP = report.false_alarms.filter((f) =>
      f.file.includes('modelcontextprotocol')
    );
    expect(mcpFP).toHaveLength(0);
  });

  it('per-sample latency stays inside the catastrophe ceiling', () => {
    // Latency is REPORTED here, never judged in absolute milliseconds. This
    // used to be `avg_latency_ms < (process.env.CI ? 1000 : 150)`, and both
    // halves of that were measuring the machine rather than the rules.
    //
    // Ten runs of this benchmark on one 10-core box, all on the same commit
    // with the rule set byte-identical (780 rules, 498 samples):
    //
    //   1-min load 94-140 : 1177.75, 1166.70, 1132.32, 1092.40, 992.39 ms
    //   1-min load 16-25  :  245.39,  245.03,  227.51,  244.94, 239.55 ms
    //
    // A 5.18x spread with nothing changed but how busy the box was. Against the
    // old CI ceiling of 1000ms, four of the five loaded runs were red and the
    // fifth (992.39) was green -- the verdict flipped on machine load alone,
    // which is the same defect PR #401 removed from tests/eval-harness.test.ts.
    //
    // The 150ms local half was worse: all ten runs above are red against it,
    // including every quiet one. That number was chosen when the rule set was
    // around 130 rules; at 780 it has been outgrown, so it had stopped being a
    // regression gate and become a standing failure waiting to be noticed. A
    // budget that fails on rule growth alone is the exact failure mode
    // scripts/lib/rule-latency-thresholds.ts exists to keep out of this repo.
    //
    // THE BUDGET. Per-sample scan cost is roughly linear in the rule count, so
    // the ceiling is expressed per rule and scales with the rule set -- growing
    // the rules, which is the point of the project, never walks into it. The
    // quiet runs above are the worst case at 245.39ms over 780 rules, i.e.
    // 0.315ms per rule per sample. 3.0 is ~9.5x that, matching the order of
    // headroom #401 chose for the sibling assertion, and lands at 2340ms for
    // today's rule set -- 1.99x above the worst reading taken here on a machine
    // that had 8.6 of its 10 cores held by runaway spin loops. The floor keeps
    // a small rule set from making the ceiling strict by accident.
    //
    // Do not tighten this toward the observed range. A threshold inside the
    // machine's noise band is what made this assertion measure the machine.
    const PER_RULE_BUDGET_MS = 3.0;
    const ceiling = Math.max(500, report.rule_count * PER_RULE_BUDGET_MS);

    // Non-tautological: an engine that stopped scanning, or stopped timing,
    // reads zero here. A busy runner cannot produce that.
    expect(report.avg_latency_ms).toBeGreaterThan(0);
    expect(report.rule_count).toBeGreaterThan(0);

    // Catastrophe only. The construct this repo profiles as pathological,
    // `(?:[a-z]+\s*){0,8}`, costs 9.8s on a single 61-character input; one rule
    // like that firing on a quarter of these 498 samples adds 2450ms to the
    // mean by itself and trips this. Anything cheaper than an engine-wide
    // blow-up is not this assertion's job and never was: one slow rule out of
    // 780 vanishes into a mean. Per-rule cost is gated by
    // scripts/gate-rule-latency.ts, which divides each rule by an anchor cohort
    // timed in the same pass, so a slower machine scales both sides and cancels.
    expect(report.avg_latency_ms).toBeLessThan(ceiling);
  });

  it('produces detailed report with missed attacks', () => {
    expect(report.corpus_size).toBeGreaterThan(400);
    expect(report.results.length).toBe(report.corpus_size);
    // Missed attacks should be Layer C (semantic) — regex ceiling
    for (const missed of report.missed_attacks) {
      expect(missed.layer).toBe('C');
    }
  });
});
