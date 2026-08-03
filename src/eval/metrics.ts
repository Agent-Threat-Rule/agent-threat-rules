/**
 * Evaluation Metrics -- computes precision, recall, F1, confusion matrix,
 * per-category breakdowns, and latency percentiles.
 *
 * All functions are pure (no side effects, no mutation).
 *
 * @module agent-threat-rules/eval/metrics
 */

export interface SampleResult {
  readonly id: string;
  readonly category: string;
  readonly expectedDetection: boolean;
  readonly actualDetection: boolean;
  readonly matchedRules: readonly string[];
  readonly confidence: number;
  readonly latencyMs: number;
  readonly difficulty: string;
  readonly tier: string;
}

export interface ConfusionMatrix {
  readonly tp: number; // true positive: attack detected
  readonly fp: number; // false positive: benign flagged
  readonly tn: number; // true negative: benign clean
  readonly fn: number; // false negative: attack missed
}

export interface ClassMetrics {
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
  readonly accuracy: number;
  readonly fpRate: number;
  readonly confusion: ConfusionMatrix;
  readonly sampleCount: number;
}

export interface LatencyStats {
  readonly p50: number;
  readonly p95: number;
  readonly p99: number;
  readonly mean: number;
  readonly max: number;
}

export interface CategoryBreakdown {
  readonly category: string;
  readonly metrics: ClassMetrics;
  readonly missedSamples: readonly string[];
  readonly falsePositives: readonly string[];
}

export interface DifficultyBreakdown {
  readonly difficulty: string;
  readonly metrics: ClassMetrics;
}

export interface EvalReport {
  readonly timestamp: string;
  readonly corpusSize: number;
  readonly overall: ClassMetrics;
  readonly latency: LatencyStats;
  readonly byCategory: readonly CategoryBreakdown[];
  readonly byDifficulty: readonly DifficultyBreakdown[];
  readonly missedAttacks: readonly SampleResult[];
  readonly falsePositives: readonly SampleResult[];
}

// ---------------------------------------------------------------------------
// Core metric calculations
// ---------------------------------------------------------------------------

function buildConfusionMatrix(results: readonly SampleResult[]): ConfusionMatrix {
  let tp = 0, fp = 0, tn = 0, fn = 0;

  for (const r of results) {
    if (r.expectedDetection && r.actualDetection) tp++;
    else if (!r.expectedDetection && r.actualDetection) fp++;
    else if (!r.expectedDetection && !r.actualDetection) tn++;
    else fn++;
  }

  return { tp, fp, tn, fn };
}

function computeClassMetrics(cm: ConfusionMatrix, sampleCount: number): ClassMetrics {
  const precision = cm.tp + cm.fp > 0 ? cm.tp / (cm.tp + cm.fp) : 1;
  const recall = cm.tp + cm.fn > 0 ? cm.tp / (cm.tp + cm.fn) : 1;
  const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
  const accuracy = sampleCount > 0 ? (cm.tp + cm.tn) / sampleCount : 1;
  const fpRate = cm.fp + cm.tn > 0 ? cm.fp / (cm.fp + cm.tn) : 0;

  return { precision, recall, f1, accuracy, fpRate, confusion: cm, sampleCount };
}

function computeLatency(results: readonly SampleResult[]): LatencyStats {
  if (results.length === 0) {
    return { p50: 0, p95: 0, p99: 0, mean: 0, max: 0 };
  }

  const sorted = [...results].map((r) => r.latencyMs).sort((a, b) => a - b);
  const len = sorted.length;

  return {
    p50: sorted[Math.floor(len * 0.5)] ?? 0,
    p95: sorted[Math.floor(len * 0.95)] ?? 0,
    p99: sorted[Math.floor(len * 0.99)] ?? 0,
    mean: sorted.reduce((a, b) => a + b, 0) / len,
    max: sorted[len - 1] ?? 0,
  };
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

export function computeEvalReport(results: readonly SampleResult[]): EvalReport {
  const overallCM = buildConfusionMatrix(results);
  const overall = computeClassMetrics(overallCM, results.length);
  const latency = computeLatency(results);

  // By category
  const categories = [...new Set(results.map((r) => r.category))];
  const byCategory: CategoryBreakdown[] = categories.map((cat) => {
    const catResults = results.filter((r) => r.category === cat);
    const cm = buildConfusionMatrix(catResults);
    const metrics = computeClassMetrics(cm, catResults.length);
    const missed = catResults.filter((r) => r.expectedDetection && !r.actualDetection).map((r) => r.id);
    const fps = catResults.filter((r) => !r.expectedDetection && r.actualDetection).map((r) => r.id);
    return { category: cat, metrics, missedSamples: missed, falsePositives: fps };
  });

  // By difficulty
  const difficulties = [...new Set(results.map((r) => r.difficulty))];
  const byDifficulty: DifficultyBreakdown[] = difficulties.map((diff) => {
    const diffResults = results.filter((r) => r.difficulty === diff);
    const cm = buildConfusionMatrix(diffResults);
    const metrics = computeClassMetrics(cm, diffResults.length);
    return { difficulty: diff, metrics };
  });

  const missedAttacks = results.filter((r) => r.expectedDetection && !r.actualDetection);
  const falsePositives = results.filter((r) => !r.expectedDetection && r.actualDetection);

  return {
    timestamp: new Date().toISOString(),
    corpusSize: results.length,
    overall,
    latency,
    byCategory,
    byDifficulty,
    missedAttacks,
    falsePositives,
  };
}

// ---------------------------------------------------------------------------
// Regression detection
// ---------------------------------------------------------------------------

export interface RegressionCheck {
  /**
   * Correctness only. Latency is deliberately excluded — see perfWarnings.
   */
  readonly passed: boolean;
  /** Correctness violations (recall / FP rate / F1). These are blocking. */
  readonly violations: readonly string[];
  /**
   * Performance observations (p95 latency). Advisory, never blocking.
   *
   * Recall, FP rate and F1 are deterministic: the same corpus and rules give
   * the same numbers on any machine. Wall-clock p95 is not — on a shared CI
   * runner executing the rest of the suite in parallel it measures how busy
   * the box is, and it has produced red builds on branches that were in fact
   * faster than main. Gating correctness on it made a real recall regression
   * and a noisy neighbour indistinguishable, which devalues both signals.
   *
   * What actually guards the dangerous case is scripts/gate-rule-latency.ts,
   * which measures every rule against a cohort of rules fixed by the baseline
   * and timed in the same profiling pass, so runner speed cancels out of the
   * metric instead of being tolerated.
   *
   * This comment previously claimed the ReDoS gate caught catastrophic
   * backtracking "structurally and deterministically", so that demoting the
   * latency check lost no protection. That was measurably wrong and is recorded
   * here rather than deleted: isReDoSSafe() in src/engine.ts deliberately
   * permits a bounded outer quantifier around an unbounded inner one, and
   * `^(?:[a-z]+\s*){0,8}ZQXKFJ$` — which it accepts — takes 9.8 seconds on a
   * single 61-character input.
   */
  readonly perfWarnings: readonly string[];
}

export interface BaselineThresholds {
  readonly minRecall: number;
  readonly maxFpRate: number;
  readonly minF1: number;
  readonly maxP95LatencyMs: number;
}

const DEFAULT_THRESHOLDS: BaselineThresholds = {
  minRecall: 0.60,
  maxFpRate: 0.05,
  minF1: 0.70,
  maxP95LatencyMs: 50,
};

export function checkRegression(
  report: EvalReport,
  thresholds: BaselineThresholds = DEFAULT_THRESHOLDS
): RegressionCheck {
  const violations: string[] = [];

  if (report.overall.recall < thresholds.minRecall) {
    violations.push(
      `Recall ${(report.overall.recall * 100).toFixed(1)}% < minimum ${(thresholds.minRecall * 100).toFixed(1)}%`
    );
  }

  if (report.overall.fpRate > thresholds.maxFpRate) {
    violations.push(
      `FP rate ${(report.overall.fpRate * 100).toFixed(3)}% > maximum ${(thresholds.maxFpRate * 100).toFixed(3)}%`
    );
  }

  if (report.overall.f1 < thresholds.minF1) {
    violations.push(
      `F1 ${(report.overall.f1 * 100).toFixed(1)}% < minimum ${(thresholds.minF1 * 100).toFixed(1)}%`
    );
  }

  // Advisory only — see RegressionCheck.perfWarnings for why this does not block.
  const perfWarnings: string[] = [];
  if (report.latency.p95 > thresholds.maxP95LatencyMs) {
    perfWarnings.push(
      `P95 latency ${report.latency.p95.toFixed(1)}ms > maximum ${thresholds.maxP95LatencyMs}ms`
    );
  }

  return { passed: violations.length === 0, violations, perfWarnings };
}
