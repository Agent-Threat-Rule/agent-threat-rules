/**
 * Evaluation Harness -- orchestrates running the corpus through the ATR engine
 * and produces a structured EvalReport.
 *
 * Supports:
 *   - Regex-only evaluation (Tier 2)
 *   - Regex + Embedding evaluation (Tier 2 + 2.5)
 *   - Full pipeline evaluation (all tiers)
 *   - Per-sample latency measurement
 *   - Regression check against baseline thresholds
 *
 * @module agent-threat-rules/eval/eval-harness
 */

import { resolve, join } from 'node:path';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { writeMeasurementFromEvalReport } from '../measurement/from-eval-harness.js';
import { ATREngine } from '../engine.js';
import { EmbeddingModule } from '../modules/embedding.js';
import type { AgentEvent } from '../types.js';
import type { CorpusSample } from './corpus.js';
import { EVAL_CORPUS, getCorpusStats } from './corpus.js';
import type { SampleResult, EvalReport, BaselineThresholds, RegressionCheck } from './metrics.js';
import { computeEvalReport, checkRegression } from './metrics.js';
import type { RuleQualityReport } from './rule-metrics.js';
import { computeRuleQuality } from './rule-metrics.js';

export interface EvalConfig {
  /** Directory containing ATR YAML rules */
  readonly rulesDir: string;
  /** Path to attack embeddings JSON (optional, for Tier 2.5) */
  readonly embeddingsPath?: string;
  /** Custom corpus (defaults to built-in EVAL_CORPUS) */
  readonly corpus?: readonly CorpusSample[];
  /** Baseline thresholds for regression check */
  readonly thresholds?: BaselineThresholds;
  /** Path to save report JSON */
  readonly outputPath?: string;
  /** Enable Tier 2.5 embedding evaluation (default: auto-detect) */
  readonly enableEmbedding?: boolean;
}

/**
 * Convert a corpus sample to an AgentEvent.
 */
function sampleToEvent(sample: CorpusSample): AgentEvent {
  return {
    type: sample.eventType,
    content: sample.text,
    timestamp: new Date().toISOString(),
    fields: sample.fields,
  };
}

/**
 * Run a single sample through the engine (regex only) and measure results.
 * Catches engine errors so a single bad sample doesn't abort the entire eval.
 */
function evaluateSampleRegex(
  engine: ATREngine,
  sample: CorpusSample
): SampleResult {
  const event = sampleToEvent(sample);

  try {
    const start = performance.now();
    const matches = engine.evaluate(event);
    const latencyMs = performance.now() - start;

    const detected = matches.length > 0;
    const topMatch = matches[0];

    return {
      id: sample.id,
      category: sample.category,
      expectedDetection: sample.expectedDetection,
      actualDetection: detected,
      matchedRules: matches.map((m) => m.rule.id),
      confidence: topMatch?.confidence ?? 0,
      latencyMs,
      difficulty: sample.difficulty,
      tier: sample.tier,
    };
  } catch {
    return {
      id: sample.id,
      category: sample.category,
      expectedDetection: sample.expectedDetection,
      actualDetection: false,
      matchedRules: [],
      confidence: 0,
      latencyMs: 0,
      difficulty: sample.difficulty,
      tier: sample.tier,
    };
  }
}

/**
 * Run a single sample through the full pipeline (regex + embedding) and measure results.
 */
async function evaluateSampleFull(
  engine: ATREngine,
  sample: CorpusSample
): Promise<SampleResult> {
  const event = sampleToEvent(sample);

  try {
    const start = performance.now();
    const { verdict } = await engine.evaluateWithVerdict(event);
    const latencyMs = performance.now() - start;

    const detected = verdict.matchCount > 0;

    return {
      id: sample.id,
      category: sample.category,
      expectedDetection: sample.expectedDetection,
      actualDetection: detected,
      matchedRules: verdict.matches.map((m) => m.rule.id),
      confidence: verdict.highestConfidence,
      latencyMs,
      difficulty: sample.difficulty,
      tier: sample.tier,
    };
  } catch {
    return {
      id: sample.id,
      category: sample.category,
      expectedDetection: sample.expectedDetection,
      actualDetection: false,
      matchedRules: [],
      confidence: 0,
      latencyMs: 0,
      difficulty: sample.difficulty,
      tier: sample.tier,
    };
  }
}

/**
 * Try to load the embedding module. Returns null if unavailable.
 */
async function tryLoadEmbedding(embeddingsPath: string): Promise<EmbeddingModule | null> {
  if (!existsSync(embeddingsPath)) return null;

  try {
    const data = JSON.parse(readFileSync(embeddingsPath, 'utf-8'));
    const module = new EmbeddingModule({
      attackVectorsData: data,
      similarityThreshold: 0.65,
    });
    await module.initialize();
    return module.isAvailable() ? module : null;
  } catch {
    return null;
  }
}

/**
 * Run the full evaluation harness.
 * Returns the EvalReport and RegressionCheck.
 */
export async function runEval(config: EvalConfig): Promise<{
  report: EvalReport;
  regression: RegressionCheck;
  corpusStats: ReturnType<typeof getCorpusStats>;
  tiersUsed: readonly string[];
  ruleQuality: RuleQualityReport;
}> {
  const corpus = config.corpus ?? EVAL_CORPUS;
  const base = resolve(config.rulesDir, '..');
  const embeddingsPath = config.embeddingsPath ?? join(base, 'data', 'attack-embeddings.json');

  // Try to load embedding module
  const shouldEmbed = config.enableEmbedding !== false;
  let embeddingModule: EmbeddingModule | null = null;
  const tiersUsed: string[] = ['tier2-regex'];

  if (shouldEmbed) {
    embeddingModule = await tryLoadEmbedding(embeddingsPath);
    if (embeddingModule) {
      tiersUsed.push('tier2.5-embedding');
    }
  }

  // Initialize engine
  const engine = new ATREngine({
    rulesDir: config.rulesDir,
    embeddingModule: embeddingModule ?? undefined,
  });
  const ruleCount = await engine.loadRules();

  if (ruleCount === 0) {
    throw new Error(`No rules loaded from ${config.rulesDir}`);
  }

  // Run all samples
  const results: SampleResult[] = [];
  const useFullPipeline = embeddingModule !== null;

  for (const sample of corpus) {
    const result = useFullPipeline
      ? await evaluateSampleFull(engine, sample)
      : evaluateSampleRegex(engine, sample);
    results.push(result);
  }

  // Cleanup embedding module
  if (embeddingModule) {
    await embeddingModule.destroy();
  }

  // Compute report
  const report = computeEvalReport(results);
  const regression = checkRegression(report, config.thresholds);
  const corpusStats = getCorpusStats();

  // Compute per-rule quality
  const loadedRuleIds = engine.getRules().map((r) => r.id);
  const ruleQuality = computeRuleQuality(results, loadedRuleIds);

  // Save report if output path specified
  if (config.outputPath) {
    const output = {
      report,
      regression,
      corpusStats,
      ruleQuality,
      ruleCount,
      engine: 'ATREngine',
      tiers: tiersUsed,
    };
    writeFileSync(config.outputPath, JSON.stringify(output, null, 2));
  }

  return { report, regression, corpusStats, tiersUsed, ruleQuality };
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

function formatPercent(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

function formatMs(n: number): string {
  return `${n.toFixed(2)}ms`;
}

export async function runEvalCLI(): Promise<void> {
  const base = resolve(join(import.meta.dirname ?? '.', '..', '..'));
  const rulesDir = join(base, 'rules');
  const outputPath = join(base, 'data', 'eval-report.json');

  console.log('\n=== ATR Evaluation Harness ===\n');

  const { report, regression, corpusStats, tiersUsed, ruleQuality } = await runEval({
    rulesDir,
    outputPath,
  });

  // Corpus stats
  console.log(`Corpus: ${corpusStats.total} samples (${corpusStats.attacks} attacks, ${corpusStats.benign} benign)`);
  console.log(`Categories: ${Object.keys(corpusStats.byCategory).join(', ')}`);
  console.log(`Tiers: ${tiersUsed.join(' + ')}`);

  // Overall metrics
  console.log(`\n--- Overall ---`);
  console.log(`  Precision:  ${formatPercent(report.overall.precision)}`);
  console.log(`  Recall:     ${formatPercent(report.overall.recall)}`);
  console.log(`  F1:         ${formatPercent(report.overall.f1)}`);
  console.log(`  Accuracy:   ${formatPercent(report.overall.accuracy)}`);
  console.log(`  FP Rate:    ${formatPercent(report.overall.fpRate)}`);
  console.log(`  Confusion:  TP=${report.overall.confusion.tp} FP=${report.overall.confusion.fp} TN=${report.overall.confusion.tn} FN=${report.overall.confusion.fn}`);

  // Latency
  console.log(`\n--- Latency ---`);
  console.log(`  P50:  ${formatMs(report.latency.p50)}`);
  console.log(`  P95:  ${formatMs(report.latency.p95)}`);
  console.log(`  P99:  ${formatMs(report.latency.p99)}`);
  console.log(`  Mean: ${formatMs(report.latency.mean)}`);
  console.log(`  Max:  ${formatMs(report.latency.max)}`);

  // Per category
  console.log(`\n--- By Category ---`);
  for (const cat of report.byCategory) {
    const missed = cat.missedSamples.length > 0 ? ` (missed: ${cat.missedSamples.join(', ')})` : '';
    const fps = cat.falsePositives.length > 0 ? ` (FP: ${cat.falsePositives.join(', ')})` : '';
    console.log(`  ${cat.category}: recall=${formatPercent(cat.metrics.recall)} precision=${formatPercent(cat.metrics.precision)} f1=${formatPercent(cat.metrics.f1)}${missed}${fps}`);
  }

  // Per difficulty
  console.log(`\n--- By Difficulty ---`);
  for (const diff of report.byDifficulty) {
    console.log(`  ${diff.difficulty}: recall=${formatPercent(diff.metrics.recall)} precision=${formatPercent(diff.metrics.precision)} f1=${formatPercent(diff.metrics.f1)}`);
  }

  // Missed attacks
  if (report.missedAttacks.length > 0) {
    console.log(`\n--- Missed Attacks (${report.missedAttacks.length}) ---`);
    for (const m of report.missedAttacks) {
      console.log(`  [${m.id}] ${m.category}/${m.difficulty}/${m.tier}`);
    }
  }

  // False positives
  if (report.falsePositives.length > 0) {
    console.log(`\n--- False Positives (${report.falsePositives.length}) ---`);
    for (const fp of report.falsePositives) {
      console.log(`  [${fp.id}] rules: ${fp.matchedRules.join(', ')}`);
    }
  }

  // Rule quality
  console.log(`\n--- Rule Quality ---`);
  console.log(`  Total rules loaded: ${ruleQuality.totalRulesEvaluated}`);
  console.log(`  Rules fired: ${ruleQuality.rulesFired}`);
  console.log(`  Rules never fired: ${ruleQuality.rulesNeverFired}`);

  if (ruleQuality.topRules.length > 0) {
    console.log(`\n  Top 10 rules by match count:`);
    for (const rule of ruleQuality.topRules.slice(0, 10)) {
      const precision = rule.matchCount > 0
        ? formatPercent(rule.tpCount / rule.matchCount)
        : 'N/A';
      console.log(`    ${rule.ruleId}: matches=${rule.matchCount} TP=${rule.tpCount} FP=${rule.fpCount} precision=${precision} avgConf=${rule.avgConfidence.toFixed(2)}`);
    }
  }

  if (ruleQuality.weakRules.length > 0) {
    console.log(`\n  Weak rules (FP > 0 or matchCount <= 1):`);
    for (const rule of ruleQuality.weakRules.slice(0, 10)) {
      console.log(`    ${rule.ruleId}: matches=${rule.matchCount} TP=${rule.tpCount} FP=${rule.fpCount} categories=[${rule.categories.join(', ')}]`);
    }
  }

  if (ruleQuality.neverFiredRuleIds.length > 0) {
    console.log(`\n  Never-fired rules (${ruleQuality.neverFiredRuleIds.length}):`);
    for (const id of ruleQuality.neverFiredRuleIds.slice(0, 20)) {
      console.log(`    ${id}`);
    }
    if (ruleQuality.neverFiredRuleIds.length > 20) {
      console.log(`    ... and ${ruleQuality.neverFiredRuleIds.length - 20} more`);
    }
  }

  // Regression check
  console.log(`\n--- Regression Check ---`);
  if (regression.passed) {
    console.log('  PASSED');
  } else {
    console.log('  FAILED:');
    for (const v of regression.violations) {
      console.log(`    - ${v}`);
    }
  }

  console.log(`\nReport saved to: ${outputPath}`);

  // Standardized Measurement file (version-pinned, immutable). This is the
  // canonical record consumed by stats.json, README badges, and the website.
  const { measurementPath } = writeMeasurementFromEvalReport(report, {
    source: 'atr-self-test',
    source_version: 'internal',
    notes: "Engine regression eval against the union of every rule's own test_cases.",
  });
  console.log(`Measurement: ${measurementPath}`);
  console.log('Done.\n');

  if (!regression.passed) {
    process.exitCode = 1;
  }
}
