/**
 * ATR (Agent Threat Rules) - Detection format for AI Agent threats
 *
 * ATR is the detection layer: it evaluates agent events against rules
 * and returns match results. It does NOT execute response actions,
 * send notifications, or manage dashboards. Those are the responsibility
 * of products built on ATR (e.g., LlamaFirewall, or your own).
 *
 * ATR 是偵測層：評估 agent 事件、回傳匹配結果。
 * 不執行回應動作、不發通知、不管 dashboard。
 * 那些是建立在 ATR 之上的產品的責任。
 *
 * @module agent-threat-rules
 */

// ── Core Detection Layer (stable API) ───────────────────────────
export { ATREngine } from './engine.js';
export type { ATREngineConfig, ATRReporter, ATRDetectionReport, ATRCleanReport } from './engine.js';
export { createTCReporter } from './tc-reporter.js';
export type { TCReporterConfig } from './tc-reporter.js';
export { loadRuleFile, loadRulesFromDirectory, validateRule } from './loader.js';
export { SessionTracker } from './session-tracker.js';
export type { SessionStateSnapshot } from './session-tracker.js';
export { computeContentHash } from './content-hash.js';
export { redactMatchedValue, redactMatchedValues } from './redact.js';
export type { RedactOptions } from './redact.js';

// ── Tier 0: Invariant Enforcement (hard boundaries) ──────────────
export { InvariantChecker } from './tier0-invariant.js';
export type { SkillManifest, InvariantViolation, InvariantViolationType } from './tier0-invariant.js';

// ── Tier 1: Blacklist Provider (known-bad lookup) ────────────────
export { InMemoryBlacklist, buildBlacklistMatch } from './tier1-blacklist.js';
export type { BlacklistProvider, BlacklistEntry } from './tier1-blacklist.js';

// ── Shared Capability Extraction ─────────────────────────────────
export { extractCapabilities } from './capability-extractor.js';
export type { ExtractedCapabilities } from './capability-extractor.js';

// ── Tier 2.5: Embedding Similarity ───────────────────────────────
export { EmbeddingModule } from './modules/embedding.js';
export type { EmbeddingModuleConfig } from './modules/embedding.js';
export { VectorStore, loadVectorEntries } from './embedding/vector-store.js';
export type { VectorEntry, SearchResult } from './embedding/vector-store.js';
export { TransformersJSModel, MockEmbeddingModel } from './embedding/model-loader.js';
export type { EmbeddingModel } from './embedding/model-loader.js';

// ── Optional Detection Modules (Layer 2-3, beta) ────────────────
export { ModuleRegistry } from './modules/index.js';
export type { ATRModule, ModuleCondition, ModuleResult } from './modules/index.js';
export { SessionModule } from './modules/session.js';
/** @beta - Experimental, not production-tested */
export { SemanticModule } from './modules/semantic.js';
export type { SemanticModuleConfig } from './modules/semantic.js';
/** @beta - Experimental, not production-tested */
export { SkillFingerprintStore } from './skill-fingerprint.js';
export type {
  SkillFingerprint,
  BehaviorAnomaly,
  SkillFingerprintConfig,
} from './skill-fingerprint.js';
export type { SemanticLayerConfig } from './layer-integration.js';

// ── Tooling (rule authoring and coverage analysis) ──────────────
export { RuleScaffolder } from './rule-scaffolder.js';
export type { ScaffoldInput, ScaffoldResult, ScaffoldOptions } from './rule-scaffolder.js';
export { CoverageAnalyzer } from './coverage-analyzer.js';
export type { CoverageGap, CoverageReport } from './coverage-analyzer.js';

// ── Converters (Splunk SPL, Elasticsearch, SARIF) ───────────────
export { convertRule, convertAllRules } from './converters/index.js';
export type { ConvertedQuery, SIEMFormat, OutputFormat } from './converters/index.js';
export { ruleToSPL } from './converters/splunk.js';
export { ruleToElastic } from './converters/elastic.js';
export { scanResultToSARIF } from './converters/sarif.js';

// ── Flywheel (auto rule generation + shadow + promotion) ─────────
export { ShadowEvaluator } from './shadow-evaluator.js';
export type { PromotionCandidate } from './shadow-evaluator.js';
export { FlywheelManager } from './flywheel.js';
export type { FlywheelConfig } from './flywheel.js';

// ── Integration Helpers (for products built on ATR) ─────────────
// These help products like LlamaFirewall, etc. build
// protection layers on top of ATR detection results.
export { computeVerdict, SEVERITY_RANK, isAutoResponseEnabled } from './verdict.js';
export { ActionExecutor } from './action-executor.js';
export type { ActionExecutorConfig } from './action-executor.js';
export { DefaultAdapter } from './adapters/default-adapter.js';
export { StdioAdapter } from './adapters/stdio-adapter.js';
export { HookHandler } from './hook-handler.js';
export type { HookHandlerConfig } from './hook-handler.js';

// Quality Standard — RFC-001 reference implementation
export * as quality from './quality/index.js';

export type {
  ATRRule,
  ATRMatch,
  AgentEvent,
  AgentEventType,
  ATRAction,
  ATRCategory,
  ATRSeverity,
  ATRStatus,
  ATRConfidence,
  ATRSourceType,
  ATRMatchType,
  ATROperator,
  ATRReferences,
  ATRTags,
  ATRAgentSource,
  ATRDetection,
  ATRResponse,
  ATRTestCases,
  ATRTestCase,
  ATRPatternCondition,
  ATRBehavioralCondition,
  ATRSequenceCondition,
  ATRSequenceStep,
  VerdictOutcome,
  ATRVerdict,
  ActionResult,
  ExecutionContext,
  PlatformAdapter,
  HookInput,
  HookOutput,
  ScanType,
  ScanResult,
} from './types.js';
