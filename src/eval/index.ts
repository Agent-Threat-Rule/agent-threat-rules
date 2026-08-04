/**
 * Evaluation framework public API
 * @module agent-threat-rules/eval
 */

export { EVAL_CORPUS, getAttackSamples, getBenignSamples, getSamplesByCategory, getSamplesByDifficulty, getCorpusStats } from './corpus.js';
export type { CorpusSample } from './corpus.js';

export { computeEvalReport, checkRegression } from './metrics.js';
export type {
  SampleResult,
  ConfusionMatrix,
  ClassMetrics,
  LatencyStats,
  CategoryBreakdown,
  DifficultyBreakdown,
  EvalReport,
  RegressionCheck,
  BaselineThresholds,
} from './metrics.js';

export { runEval, runEvalCLI } from './eval-harness.js';
export type { EvalConfig, EvalEventShapeMode } from './eval-harness.js';
export { defaultEventShapeMode } from './eval-harness.js';

export { computeRuleQuality } from './rule-metrics.js';
export type { RuleQuality, RuleQualityReport } from './rule-metrics.js';
