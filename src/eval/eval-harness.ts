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
import { corpusShapes, sourceAgnosticEvent } from '../corpus-event.js';
import { EmbeddingModule } from '../modules/embedding.js';
import type { AgentEvent } from '../types.js';
import type { CorpusSample } from './corpus.js';
import { EVAL_CORPUS, getCorpusStats } from './corpus.js';
import type { SampleResult, EvalReport, BaselineThresholds, RegressionCheck } from './metrics.js';
import { computeEvalReport, checkRegression } from './metrics.js';
import type { RuleQualityReport } from './rule-metrics.js';
import { computeRuleQuality } from './rule-metrics.js';

/**
 * How a corpus sample is presented to the engine.
 *
 *   'legacy'    — one event: `{ type: sample.eventType, content: sample.text }`.
 *                 What this harness did until 2026-08-05. Reproduces every
 *                 previously published eval / PINT number.
 *   'wide'      — legacy PLUS the same event re-typed to mcp_exchange, which
 *                 removes ONLY the engine's source-type filter. Isolates how
 *                 much of the gap is rule ADMISSION rather than field pouring.
 *   'canonical' — legacy PLUS scripts' canonical shape set (src/corpus-event.ts)
 *                 PLUS scanSkill(). The presentation every FP gate in this repo
 *                 already uses.
 *
 * WHY THIS EXISTS AT ALL
 *
 * src/engine.ts derives a source type from event.type (EVENT_TYPE_TO_SOURCE)
 * and then skips every rule whose `agent_source.type` differs. The PINT corpus
 * labels all 850 samples `llm_input` -> source `llm_io`, so on main 383 of the
 * 773 non-draft rules — every mcp_exchange, tool_call, multi_agent_comm,
 * memory_access, context_window and skill_lifecycle rule — were dropped before
 * a single pattern was compared. They could not produce a true positive and,
 * more importantly, could not produce a false positive either: the published
 * "precision 100%" was measured over half a rulebase.
 *
 * That is the same zero-measurement defect src/corpus-event.ts was written to
 * abolish; this harness simply escaped the ratchet because it lives under src/
 * and the ratchet only greps scripts/.
 *
 * The mode is explicit, and recorded in the measurement notes, because flipping
 * it changes a PUBLISHED number. Override with ATR_EVAL_EVENT_SHAPE=legacy|wide.
 */
export type EvalEventShapeMode = 'legacy' | 'wide' | 'canonical';

/** Default presentation. Env override exists so an old number can be reproduced. */
export function defaultEventShapeMode(): EvalEventShapeMode {
  const raw = process.env['ATR_EVAL_EVENT_SHAPE']?.trim().toLowerCase();
  if (raw === 'legacy' || raw === 'wide' || raw === 'canonical') return raw;
  return 'canonical';
}

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
  /** Event presentation (default: defaultEventShapeMode()) */
  readonly eventShape?: EvalEventShapeMode;
}

/**
 * The sample exactly as its author declared it. Still the PRIMARY event in every
 * mode: it is the only presentation that carries the sample's own `fields` and
 * the type-specific aliases in resolveField (an llm_input event resolves
 * `user_input` from event.content; an mcp_exchange event does not). Keeping it
 * in every mode is what makes the wider modes strict supersets — widening can
 * reveal a match, never hide one.
 */
function declaredEvent(sample: CorpusSample): AgentEvent {
  return {
    type: sample.eventType,
    content: sample.text,
    timestamp: new Date().toISOString(),
    fields: sample.fields,
  };
}

/**
 * The events a sample is pushed through, primary first.
 *
 * Note what an eval needs that a rule-ID audit does not: the question here is
 * "was this sample judged an attack at all", so the answer is the UNION over
 * presentations, counted once per sample. A document that trips three rules on
 * four shapes is one detection, not twelve — matching how scripts/ counts a
 * false positive per sample rather than per shape.
 */
function sampleEvents(
  sample: CorpusSample,
  mode: EvalEventShapeMode
): readonly AgentEvent[] {
  const primary = declaredEvent(sample);
  if (mode === 'legacy') return [primary];
  if (mode === 'wide') return [primary, sourceAgnosticEvent(primary)];
  return [primary, ...corpusShapes(sample.text).map((s) => s.event)];
}

/** scanSkill() is a separate engine entry point, not an event shape. */
function usesSkillScan(mode: EvalEventShapeMode): boolean {
  return mode === 'canonical';
}

/** Rule ids from the secondary presentations, via the safe public sync entry point. */
function secondaryMatchIds(
  engine: ATREngine,
  sample: CorpusSample,
  mode: EvalEventShapeMode
): Map<string, number> {
  const extra = new Map<string, number>();
  for (const event of sampleEvents(sample, mode).slice(1)) {
    for (const m of engine.evaluate(event)) {
      extra.set(m.rule.id, Math.max(extra.get(m.rule.id) ?? 0, m.confidence));
    }
  }
  if (usesSkillScan(mode)) {
    for (const m of engine.scanSkill(sample.text)) {
      extra.set(m.rule.id, Math.max(extra.get(m.rule.id) ?? 0, m.confidence));
    }
  }
  return extra;
}

/**
 * Run a single sample through the engine (regex only) and measure results.
 * Catches engine errors so a single bad sample doesn't abort the entire eval.
 */
function evaluateSampleRegex(
  engine: ATREngine,
  sample: CorpusSample,
  mode: EvalEventShapeMode
): SampleResult {
  try {
    const start = performance.now();
    const byRule = new Map<string, number>();
    for (const event of sampleEvents(sample, mode)) {
      for (const m of engine.evaluate(event)) {
        byRule.set(m.rule.id, Math.max(byRule.get(m.rule.id) ?? 0, m.confidence));
      }
    }
    if (usesSkillScan(mode)) {
      for (const m of engine.scanSkill(sample.text)) {
        byRule.set(m.rule.id, Math.max(byRule.get(m.rule.id) ?? 0, m.confidence));
      }
    }
    const latencyMs = performance.now() - start;

    return {
      id: sample.id,
      category: sample.category,
      expectedDetection: sample.expectedDetection,
      actualDetection: byRule.size > 0,
      matchedRules: [...byRule.keys()],
      confidence: Math.max(0, ...byRule.values()),
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
 *
 * The Tier 2.5 embedding pass runs ONCE, on the declared event. It is not
 * source-type filtered and it reads exactly one field (`content`), and every
 * secondary presentation carries either the identical raw text or a JSON
 * re-encoding of it — so encoding the sample four more times would multiply the
 * runtime without changing a single verdict. The secondary presentations exist
 * to fix rule ADMISSION, which is a Tier 2 (regex) concern, so they go through
 * evaluate(): the public sync entry point, which still applies the lane gate and
 * still withholds unconfirmed `confirm: embedding` rules outside the hunt lane.
 */
async function evaluateSampleFull(
  engine: ATREngine,
  sample: CorpusSample,
  mode: EvalEventShapeMode
): Promise<SampleResult> {
  try {
    const start = performance.now();
    const { verdict } = await engine.evaluateWithVerdict(declaredEvent(sample));
    const byRule = new Map<string, number>(
      verdict.matches.map((m) => [m.rule.id, m.confidence])
    );
    for (const [id, confidence] of secondaryMatchIds(engine, sample, mode)) {
      byRule.set(id, Math.max(byRule.get(id) ?? 0, confidence));
    }
    const latencyMs = performance.now() - start;

    return {
      id: sample.id,
      category: sample.category,
      expectedDetection: sample.expectedDetection,
      actualDetection: byRule.size > 0,
      matchedRules: [...byRule.keys()],
      confidence: Math.max(verdict.highestConfidence, 0, ...byRule.values()),
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
  eventShape: EvalEventShapeMode;
}> {
  const eventShape = config.eventShape ?? defaultEventShapeMode();
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
      ? await evaluateSampleFull(engine, sample, eventShape)
      : evaluateSampleRegex(engine, sample, eventShape);
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
      eventShape,
    };
    writeFileSync(config.outputPath, JSON.stringify(output, null, 2));
  }

  return { report, regression, corpusStats, tiersUsed, ruleQuality, eventShape };
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

  const { report, regression, corpusStats, tiersUsed, ruleQuality, eventShape } = await runEval({
    rulesDir,
    outputPath,
  });

  // Corpus stats
  console.log(`Corpus: ${corpusStats.total} samples (${corpusStats.attacks} attacks, ${corpusStats.benign} benign)`);
  console.log(`Categories: ${Object.keys(corpusStats.byCategory).join(', ')}`);
  console.log(`Tiers: ${tiersUsed.join(' + ')}`);
  console.log(`Event shape: ${eventShape}`);

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
    notes:
      "Engine regression eval against the union of every rule's own test_cases. " +
      `Event shape: ${eventShape} (see src/eval/eval-harness.ts EvalEventShapeMode — ` +
      'the mode decides how many rules the engine admits per sample, so a number ' +
      'measured under one mode is not comparable with a number measured under another).',
  });
  console.log(`Measurement: ${measurementPath}`);
  console.log('Done.\n');

  if (!regression.passed) {
    process.exitCode = 1;
  }
}
