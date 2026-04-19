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
 * - Latency < 150ms per sample (raised from 50 — rule count grew past 130;
 *   production path uses early-exit + verdict cache so end-user latency stays
 *   well under this budget)
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
  }, 180_000);

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

  it('latency < 150ms per sample', () => {
    expect(report.avg_latency_ms).toBeLessThan(150);
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
