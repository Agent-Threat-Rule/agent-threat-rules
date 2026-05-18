/**
 * ATR Engine - Evaluates agent events against ATR rules
 *
 * Core detection engine that:
 * 1. Loads ATR YAML rules from disk
 * 2. Evaluates agent events (LLM I/O, tool calls, behaviors) against rules
 * 3. Returns matched rules with confidence scores
 * 4. Supports two condition formats:
 *    - Array format: conditions is an array of {field, operator, value} objects
 *    - Named format: conditions is an object map of named condition blocks
 *
 * @module agent-threat-rules/engine
 */

import type {
  ATRRule,
  ATRMatch,
  AgentEvent,
  ATRPatternCondition,
  ATRBehavioralCondition,
  ATRVerdict,
  ActionResult,
  ScanResult,
  ScanType,
  ATRLanguage,
} from './types.js';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { computeContentHash } from './content-hash.js';
import { loadRulesFromDirectory, loadRuleFile } from './loader.js';
import type { SessionTracker } from './session-tracker.js';
import { computeVerdict } from './verdict.js';
import type { ActionExecutor } from './action-executor.js';
import type { SkillFingerprintStore } from './skill-fingerprint.js';
import { SemanticModule } from './modules/semantic.js';
import type { SemanticLayerConfig } from './layer-integration.js';
import {
  resolveSkillId,
  runFingerprintLayer,
  shouldRunSemanticLayer,
  createSemanticModuleFromConfig,
  runSemanticLayer,
} from './layer-integration.js';
import type { InvariantChecker } from './tier0-invariant.js';
import type { BlacklistProvider } from './tier1-blacklist.js';
import { buildBlacklistMatch, resolveSkillId as resolveBlacklistSkillId } from './tier1-blacklist.js';
import type { EmbeddingModule } from './modules/embedding.js';

/**
 * Rules excluded from skill-context scanning due to high false-positive rate.
 * Threshold: >0.5% FP on 466 real-world SKILL.md files (skills-sh corpus).
 * Re-evaluate when adding new rules or updating detection patterns.
 */
/**
 * Rules excluded from skill-context scanning due to high false-positive rate.
 *
 * Audit 2026-04-14: denylist reduced from 22 → 10 rules.
 * Rules with ≤2 FP on 466 benign SKILL.md samples were removed from denylist
 * to improve wild scan coverage (previously missing 2000+ potential threats).
 *
 * Threshold: >2 FP on 466 benchmark benign samples (>0.43%).
 * Re-evaluate when adding new rules or updating detection patterns.
 */
const SKILL_CONTEXT_DENYLIST: ReadonlySet<string> = new Set([
  // HIGH FP (>20%) — must stay denylisted until regex rewrite
  'ATR-2026-00111', // Shell Escape — 70% FP (matches any shell/exec mention in code examples)
  'ATR-2026-00118', // Approval Fatigue — 27% FP (matches any approval/confirm pattern)
  'ATR-2026-00051', // Resource Exhaustion — 23% FP (SQL/loop patterns in normal skills)
  // MEDIUM FP (1-6%) — denylisted, need regex tightening to unlock
  'ATR-2026-00030', // Cross-Agent Attack — 6% FP (multi-agent communication patterns)
  'ATR-2026-00032', // Goal Hijacking — 3.2% FP (instructional language)
  'ATR-2026-00002', // Indirect Prompt Injection — 2.4% FP (content-fetch patterns)
  'ATR-2026-00115', // Env Var Harvesting — 1.7% FP (legitimate env var references)
  'ATR-2026-00113', // Credential Theft — 1.5% FP (security skills reference credential files)
  'ATR-2026-00110', // eval() Injection — 1.3% FP (coding skills mention eval/exec)
  'ATR-2026-00114', // OAuth Token Interception — 1.3% FP (normal auth patterns)
  'ATR-2026-00050', // Runaway Agent Loop — 1.1% FP (loop patterns in automation skills)
  'ATR-2026-00112', // Dynamic Import — 0.9% FP (import/require references)
  'ATR-2026-00142', // Piggyback Transition — 0.6% FP (descriptive text triggers)
  'ATR-2026-00116', // A2A Message Injection — 0.4% FP (agent communication patterns)
  // LOW FP but zero wild hits — kept in denylist for precision
  'ATR-2026-00060', // MCP Skill Impersonation — 1 FP, 0 wild hits
  'ATR-2026-00074', // Cross-Agent Privilege Escalation — 1 FP, 0 wild hits
  'ATR-2026-00076', // Insecure Inter-Agent Communication — 1 FP, 0 wild hits
  'ATR-2026-00077', // Human-Agent Trust Exploitation — 1 FP, 0 wild hits
  'ATR-2026-00098', // Unauthorized Financial Action — 1 FP, 0 wild hits
  'ATR-2026-00117', // Agent Identity Spoofing — 1 FP, 0 wild hits
  'ATR-2026-00123', // Over-Privileged Skill — 1 FP, 0 wild hits
  'ATR-2026-00148', // Multilingual Prompt Injection — 1 FP, 0 wild hits
  // REMOVED from denylist (≤1 FP + has wild value):
  // ATR-2026-00117 Agent Identity Spoofing (1 FP)
  // ATR-2026-00060 MCP Skill Impersonation (1 FP)
  // ATR-2026-00077 Human-Agent Trust Exploitation (1 FP)
  // ATR-2026-00076 Insecure Inter-Agent Communication (1 FP)
  // ATR-2026-00148 Multilingual Prompt Injection (1 FP)
  // ATR-2026-00123 Over-Privileged Skill (1 FP)
  // ATR-2026-00074 Cross-Agent Privilege Escalation (1 FP)
  // ATR-2026-00098 Unauthorized Financial Action (1 FP)
]);

/**
 * Detect and decode base64-encoded blocks in content.
 * Bounds: max 1 level decode, max 5 blocks, min 32 chars per block,
 * MAX_EVAL_LENGTH per decoded block. Returns decoded text fragments.
 */
const BASE64_BLOCK_RE = /(?:[A-Za-z0-9+/]{32,}={0,2})/g;
const MAX_DECODE_BLOCKS = 5;

function decodeBase64Blocks(content: string): string[] {
  const decoded: string[] = [];
  let match: RegExpExecArray | null;
  let count = 0;

  while ((match = BASE64_BLOCK_RE.exec(content)) !== null && count < MAX_DECODE_BLOCKS) {
    try {
      const raw = Buffer.from(match[0], 'base64');
      const text = raw.toString('utf-8');
      // Only keep if decoded content looks like text (not binary garbage)
      // Check: >80% printable ASCII or valid UTF-8 with common chars
      const printable = text.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
      if (printable / text.length > 0.7 && text.length >= 10) {
        decoded.push(text.slice(0, 100_000)); // MAX_EVAL_LENGTH bound
        count++;
      }
    } catch {
      // Invalid base64, skip
    }
  }

  return decoded;
}

/** Map agent event types to ATR source types */
const EVENT_TYPE_TO_SOURCE: Record<string, string> = {
  llm_input: 'llm_io',
  llm_output: 'llm_io',
  tool_call: 'tool_call',
  tool_response: 'mcp_exchange',
  agent_behavior: 'agent_behavior',
  multi_agent_message: 'multi_agent_comm',
};

/** Map agent event types to default field names */
const EVENT_TYPE_TO_FIELD: Record<string, string> = {
  llm_input: 'user_input',
  llm_output: 'agent_output',
  tool_call: 'tool_name',
  tool_response: 'tool_response',
  agent_behavior: 'metric',
  multi_agent_message: 'agent_message',
};

/**
 * Detection reporter — opt-in callback for feeding scan results back to
 * ATR Threat Cloud. Every integration endpoint that enables this becomes
 * a sensor in the global detection network. Anonymized detection events
 * are aggregated across all endpoints to crystallize new rules.
 *
 * Privacy: only ruleId, severity, and scanTarget are reported by default.
 * No raw content, no PII, no file paths. Platforms can override onDetection
 * to control exactly what is sent.
 */
export interface ATRReporter {
  /** Called for every match. Implement to POST anonymized data to TC. */
  readonly onDetection: (report: ATRDetectionReport) => void | Promise<void>;
  /** Called when a scan completes with zero matches (opt-in). */
  readonly onClean?: (report: ATRCleanReport) => void | Promise<void>;
}

export interface ATRDetectionReport {
  readonly ruleId: string;
  readonly severity: string;
  readonly scanTarget: string;
  readonly category: string;
  readonly confidence: number;
  readonly timestamp: string;
  /** Content hash (SHA-256) — identifies the scanned artifact without revealing content */
  readonly contentHash: string;
}

export interface ATRCleanReport {
  readonly rulesEvaluated: number;
  readonly scanTarget: string;
  readonly timestamp: string;
  readonly contentHash: string;
}

export interface ATREngineConfig {
  /** Directory containing ATR rule YAML files */
  rulesDir?: string;
  /** Pre-loaded rules (for testing or embedding) */
  rules?: ATRRule[];
  /** Optional session tracker for behavioral detection across events */
  sessionTracker?: SessionTracker;
  /** Optional Tier 0: Invariant enforcement (hard boundaries, pre-check) */
  invariantChecker?: InvariantChecker;
  /** Optional Tier 1: Skill blacklist provider (known-bad lookup) */
  blacklistProvider?: BlacklistProvider;
  /** Optional Layer 2: Skill behavioral fingerprinting (no LLM required) */
  fingerprintStore?: SkillFingerprintStore;
  /** Optional Tier 2.5: Embedding similarity module (requires @xenova/transformers) */
  embeddingModule?: EmbeddingModule;
  /** Optional Layer 3: Semantic LLM-as-judge analysis (requires API key) */
  semanticModule?: SemanticLayerConfig;
  /** Optional: detection reporter for feeding results to ATR Threat Cloud */
  reporter?: ATRReporter;
}

export class ATREngine {
  private rules: ATRRule[] = [];
  private readonly compiledPatterns = new Map<string, Map<string, RegExp[]>>();
  private readonly semanticModuleInstance: SemanticModule | null;

  /**
   * Find bundled rules directory shipped with the npm package.
   * Checks: ../rules (from dist/), ./rules (repo root)
   */
  private findBundledRulesDir(): string | undefined {
    // import.meta.dirname available in Node 21+, fallback to cwd
    const base = typeof import.meta.dirname === 'string' ? import.meta.dirname : process.cwd();
    const candidates = [
      resolve(base, '..', 'rules'),  // dist/engine.js → ../rules
      resolve(base, 'rules'),         // repo root
      resolve(process.cwd(), 'rules'),
      resolve(process.cwd(), 'node_modules', 'agent-threat-rules', 'rules'),
    ];
    for (const dir of candidates) {
      if (existsSync(dir)) return dir;
    }
    return undefined;
  }

  constructor(private readonly config: ATREngineConfig = {}) {
    // Initialize Layer 3 semantic module if config provided
    if (config.semanticModule) {
      const moduleConfig = createSemanticModuleFromConfig(config.semanticModule);
      this.semanticModuleInstance = new SemanticModule(moduleConfig);
    } else {
      this.semanticModuleInstance = null;
    }
  }

  /**
   * Load rules from configured directory and/or pre-loaded rules.
   */
  async loadRules(): Promise<number> {
    this.rules = [];
    this.compiledPatterns.clear();

    if (this.config.rules) {
      this.rules.push(...this.config.rules);
    }

    // Resolve rules directory: explicit config > bundled rules in package
    const rulesDir = this.config.rulesDir ?? this.findBundledRulesDir();
    if (rulesDir) {
      try {
        const fileRules = loadRulesFromDirectory(rulesDir);
        this.rules.push(...fileRules);
      } catch {
        // Directory may not exist yet
      }
    }

    // Pre-compile regex patterns for performance
    for (const rule of this.rules) {
      this.compilePatterns(rule);
    }

    return this.rules.length;
  }

  /**
   * Load a single rule file and add it to the engine.
   */
  addRuleFile(filePath: string): void {
    const rule = loadRuleFile(filePath);
    this.rules.push(rule);
    this.compilePatterns(rule);
  }

  /**
   * Add a pre-parsed rule to the engine.
   */
  addRule(rule: ATRRule): void {
    this.rules.push(rule);
    this.compilePatterns(rule);
  }

  /**
   * Evaluate an agent event against all loaded ATR rules.
   * Returns all matching rules with details.
   */
  evaluate(event: AgentEvent): ATRMatch[] {
    const matches: ATRMatch[] = [];
    const eventSourceType = EVENT_TYPE_TO_SOURCE[event.type];
    const allMatchedPatterns: string[] = [];

    const sessionId = event.sessionId;

    // Tier 0: Invariant enforcement (hard boundaries, pre-check)
    if (this.config.invariantChecker) {
      const violations = this.config.invariantChecker.check(event);
      if (violations.length > 0) {
        // Record denied event in session tracker for telemetry before returning
        if (this.config.sessionTracker && sessionId) {
          this.config.sessionTracker.recordEvent(sessionId, event, ['tier0-invariant-deny']);
        }
        return violations.map((v) => this.config.invariantChecker!.buildDenyMatch(v));
      }
    }

    // Tier 1: Blacklist lookup (known-bad skills)
    if (this.config.blacklistProvider) {
      const skillId = resolveBlacklistSkillId(event);
      if (skillId) {
        const entry = this.config.blacklistProvider.lookup(skillId);
        if (entry) {
          matches.push(buildBlacklistMatch(entry));
          // Don't short-circuit -- continue for telemetry, but blacklist match
          // has critical severity which guarantees DENY verdict
        }
      }
    }

    // Tier 2: Pattern matching (existing regex rules)
    const isSkillContext = event.scanContext === 'skill';
    for (const rule of this.rules) {
      // Skip deprecated and draft rules
      if (rule.status === 'deprecated' || rule.status === 'draft') continue;

      // Source type filtering: skip rules that don't apply to this event type
      // When scanContext is 'skill', skip source-type filtering — all rules fire
      if (!isSkillContext && eventSourceType && rule.agent_source.type !== eventSourceType) {
        // Allow mcp_exchange rules to also match tool_call events
        if (!(rule.agent_source.type === 'mcp_exchange' && eventSourceType === 'tool_call')) {
          continue;
        }
      }

      const matchResult = this.evaluateRule(rule, event);
      if (matchResult) {
        // Skill context compound gating: rules not designed for SKILL.md
        // must match 2+ CONDITIONS (not patterns) to trigger. A single
        // condition with many patterns fires too easily on long documents.
        // 2+ condition co-occurrence means the document exhibits multiple
        // distinct threat signals — strongly indicates a real attack, not
        // security documentation that happens to describe one attack type.
        // Rules with scan_target 'skill' or 'both' fire normally.
        // Compound gate: rules not designed for skill scanning need 30%+
        // conditions to match. Rules with scan_target 'skill' or 'both'
        // have verified FP rates and fire normally.
        if (isSkillContext && rule.tags.scan_target !== 'skill' && rule.tags.scan_target !== 'both') {
          // Require at least 30% of conditions to match (min 2) — long documents
          // with many technical terms easily hit 2 conditions; percentage-based
          // threshold scales with rule complexity.
          const totalConds: number = Number(rule.detection?.conditions?.length ?? 1);
          const minRequired = Math.max(2, Math.ceil(totalConds * 0.3));
          if ((matchResult.matchedConditions?.length ?? 0) < minRequired) {
            continue;
          }
        }
        matches.push(matchResult);
        allMatchedPatterns.push(...matchResult.matchedPatterns);
      }
    }

    // Record event in session tracker (always, for cross-event sequence detection)
    if (this.config.sessionTracker && sessionId) {
      this.config.sessionTracker.recordEvent(sessionId, event, allMatchedPatterns);
    }

    // Layer 2: Skill behavioral fingerprinting (optional, no LLM)
    const fingerprintStore = this.config.fingerprintStore;
    if (fingerprintStore) {
      const skillId = resolveSkillId(event);
      if (skillId) {
        const layer2Matches = runFingerprintLayer(fingerprintStore, event, skillId);
        matches.push(...layer2Matches);
      }
    }

    // Sort by severity (critical first) then confidence
    const sorted = matches.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
      const aSev = severityOrder[a.rule.severity] ?? 4;
      const bSev = severityOrder[b.rule.severity] ?? 4;
      if (aSev !== bSev) return aSev - bSev;
      return b.confidence - a.confidence;
    });

    // Report detections to Threat Cloud (opt-in)
    if (this.config.reporter) {
      const hash = computeContentHash(event.content ?? '');
      const scanTarget = isSkillContext ? 'skill' : (event.type ?? 'unknown');
      const now = new Date().toISOString();

      if (sorted.length > 0) {
        for (const match of sorted) {
          this.config.reporter.onDetection({
            ruleId: match.rule.id,
            severity: match.rule.severity,
            scanTarget,
            category: match.rule.tags?.category ?? 'unknown',
            confidence: match.confidence,
            timestamp: now,
            contentHash: hash,
          });
        }
      } else if (this.config.reporter.onClean) {
        this.config.reporter.onClean({
          rulesEvaluated: this.rules.length,
          scanTarget,
          timestamp: now,
          contentHash: hash,
        });
      }
    }

    return sorted;
  }

  /**
   * Evaluate a single rule against an event.
   * Supports both array-format and named-map-format conditions.
   */
  private evaluateRule(rule: ATRRule, event: AgentEvent): ATRMatch | null {
    const { detection } = rule;
    const conditions = detection.conditions;
    const allMatchedPatterns: string[] = [];

    // Detect format: array or named map
    if (Array.isArray(conditions)) {
      return this.evaluateArrayConditions(rule, conditions, detection.condition, event, allMatchedPatterns);
    }

    return this.evaluateNamedConditions(rule, conditions, detection.condition, event, allMatchedPatterns);
  }

  /**
   * Evaluate array-format conditions: [{field, operator, value}, ...]
   * with condition: "any" | "all"
   */
  private evaluateArrayConditions(
    rule: ATRRule,
    conditions: unknown[],
    conditionExpr: string,
    event: AgentEvent,
    allMatchedPatterns: string[]
  ): ATRMatch | null {
    const matchedConditionIndices: number[] = [];
    const isAny = conditionExpr === 'any' || conditionExpr === 'or';

    for (let i = 0; i < conditions.length; i++) {
      const cond = conditions[i] as Record<string, unknown>;
      const result = this.evaluateArrayCondition(cond, event, rule.id, i, allMatchedPatterns);

      if (result) {
        matchedConditionIndices.push(i);
        if (isAny) break; // Short-circuit on first match for "any"
      }
    }

    const matched = isAny
      ? matchedConditionIndices.length > 0
      : matchedConditionIndices.length === conditions.length;

    if (!matched) return null;

    const baseConfidence = rule.tags.confidence === 'high' ? 0.9 : rule.tags.confidence === 'medium' ? 0.7 : 0.5;
    const matchRatio = matchedConditionIndices.length / Math.max(conditions.length, 1);
    const confidence = Math.min(baseConfidence + matchRatio * 0.1, 1.0);

    return {
      rule,
      matchedConditions: matchedConditionIndices.map(String),
      matchedPatterns: allMatchedPatterns,
      confidence,
      timestamp: new Date().toISOString(),
      scan_context: 'native' as const,
    };
  }

  /**
   * Evaluate a single array-format condition {field, operator, value}.
   */
  private evaluateArrayCondition(
    cond: Record<string, unknown>,
    event: AgentEvent,
    ruleId: string,
    index: number,
    matchedPatterns: string[]
  ): boolean {
    // Sequence condition (has 'steps' array)
    if (cond['steps'] && Array.isArray(cond['steps'])) {
      return this.evaluateSequenceCondition(cond, event);
    }

    // Behavioral condition
    if (cond['metric'] && cond['operator'] && cond['threshold'] !== undefined) {
      return this.evaluateBehavioralCondition(cond as unknown as ATRBehavioralCondition, event);
    }

    const field = cond['field'] as string | undefined;
    const operator = cond['operator'] as string | undefined;
    const value = cond['value'] as string | undefined;
    const condLang = cond['language'] as ATRLanguage | undefined;

    if (!field || !operator || value === undefined) return false;

    const rawFieldValue = this.resolveField(field, event);
    if (!rawFieldValue) return false;

    // v3.0 multilingual dispatch: skip language-tagged conditions whose
    // declared language doesn't match the input's dominant script. Pure
    // optimisation — language-untagged conditions remain unaffected.
    if (condLang !== undefined) {
      const inputLang = detectInputLanguage(rawFieldValue);
      if (!conditionLanguageMatches(condLang, inputLang)) return false;
    }

    // Non-English conditions normalise with NFKC (aggressive) so full-width
    // Latin evasion inside CJK/Arabic text (e.g. "ｉｇｎｏｒｅ" embedded in a
    // Chinese prompt) is caught. English conditions retain NFC for
    // backwards compatibility with v2.x rules whose regex sometimes
    // distinguishes full-width vs half-width characters.
    const fieldValue =
      condLang !== undefined && condLang !== 'en'
        ? normalizeUnicodeAggressive(rawFieldValue)
        : normalizeUnicode(rawFieldValue);

    switch (operator) {
      case 'regex': {
        // Code-block suppression for array-format rules with explicit opt-in.
        // NL-style rules set tags.suppress_in_code_blocks: true so that matches
        // landing inside ```...``` fenced blocks (e.g. pentest example payloads)
        // do not fire. Built lazily so non-opt-in rules pay no cost.
        const ruleForSuppress = this.rules.find(r => r.id === ruleId);
        const suppressInCodeBlocks = (ruleForSuppress?.tags as { suppress_in_code_blocks?: boolean } | undefined)?.suppress_in_code_blocks === true;
        const codeRanges = suppressInCodeBlocks ? buildCodeBlockRanges(fieldValue) : [];

        // Try pre-compiled pattern first
        const compiled = this.compiledPatterns.get(ruleId)?.get(String(index));
        if (compiled && compiled.length > 0) {
          // Test against both normalized and raw values so that patterns
          // detecting zero-width/bidi characters can match before stripping
          if (safeRegexTest(compiled[0]!, fieldValue) || safeRegexTest(compiled[0]!, rawFieldValue)) {
            if (suppressInCodeBlocks && codeRanges.length > 0 && isInsideCodeBlock(fieldValue, compiled[0]!, codeRanges)) {
              return false;
            }
            matchedPatterns.push(value);
            return true;
          }
          return false;
        }
        // Fallback: compile on the fly
        try {
          const normalized = normalizeRegex(value);
          const rFlags = normalized.includes('\\u{') || normalized.includes('\\p{') ? 'iu' : 'i';
          const regex = new RegExp(normalized, rFlags);
          if (safeRegexTest(regex, fieldValue) || safeRegexTest(regex, rawFieldValue)) {
            if (suppressInCodeBlocks && codeRanges.length > 0 && isInsideCodeBlock(fieldValue, regex, codeRanges)) {
              return false;
            }
            matchedPatterns.push(value);
            return true;
          }
        } catch {
          // Invalid regex
        }
        return false;
      }
      case 'contains': {
        if (fieldValue.toLowerCase().includes(value.toLowerCase())) {
          matchedPatterns.push(value);
          return true;
        }
        return false;
      }
      case 'exact': {
        if (fieldValue === value) {
          matchedPatterns.push(value);
          return true;
        }
        return false;
      }
      case 'starts_with': {
        if (fieldValue.toLowerCase().startsWith(value.toLowerCase())) {
          matchedPatterns.push(value);
          return true;
        }
        return false;
      }
      default:
        return false;
    }
  }

  /**
   * Evaluate named-map-format conditions: {name: {field, patterns, match_type}, ...}
   * with condition: "name1 AND name2" | "name1 OR name2" | "name1"
   */
  private evaluateNamedConditions(
    rule: ATRRule,
    conditions: Record<string, unknown>,
    conditionExpr: string,
    event: AgentEvent,
    allMatchedPatterns: string[]
  ): ATRMatch | null {
    const conditionResults = new Map<string, boolean>();
    const matchedConditionNames: string[] = [];

    for (const [condName, condDef] of Object.entries(conditions)) {
      const result = this.evaluateNamedCondition(condName, condDef, event, rule, allMatchedPatterns);
      conditionResults.set(condName, result);
      if (result) {
        matchedConditionNames.push(condName);
      }
    }

    // Evaluate the boolean expression
    const finalResult = this.evaluateExpression(conditionExpr, conditionResults);
    if (!finalResult) return null;

    const baseConfidence = rule.tags.confidence === 'high' ? 0.9 : rule.tags.confidence === 'medium' ? 0.7 : 0.5;
    const matchRatio = matchedConditionNames.length / Math.max(Object.keys(conditions).length, 1);
    const confidence = Math.min(baseConfidence + matchRatio * 0.1, 1.0);

    return {
      rule,
      matchedConditions: matchedConditionNames,
      matchedPatterns: allMatchedPatterns,
      confidence,
      timestamp: new Date().toISOString(),
      scan_context: 'native' as const,
    };
  }

  /**
   * Evaluate a single named condition against an event.
   */
  private evaluateNamedCondition(
    condName: string,
    condDef: unknown,
    event: AgentEvent,
    rule: ATRRule,
    matchedPatterns: string[]
  ): boolean {
    const cond = condDef as Record<string, unknown>;

    // Pattern matching condition (named format with patterns array)
    if (cond['patterns'] && cond['field']) {
      return this.evaluatePatternCondition(
        cond as unknown as ATRPatternCondition,
        event,
        rule.id,
        condName,
        matchedPatterns
      );
    }

    // Behavioral condition
    if (cond['metric'] && cond['operator'] && cond['threshold'] !== undefined) {
      return this.evaluateBehavioralCondition(cond as unknown as ATRBehavioralCondition, event);
    }

    // Sequence condition
    if (cond['steps'] && Array.isArray(cond['steps'])) {
      return this.evaluateSequenceCondition(cond, event);
    }

    return false;
  }

  /**
   * Evaluate a pattern matching condition (named format with patterns array).
   */
  private evaluatePatternCondition(
    cond: ATRPatternCondition,
    event: AgentEvent,
    ruleId: string,
    condName: string,
    matchedPatterns: string[]
  ): boolean {
    const rawFieldValue = this.resolveField(cond.field, event);
    if (!rawFieldValue) return false;
    const fieldValue = normalizeUnicode(rawFieldValue);

    // Code block suppression: for runtime events, rules that commonly
    // false-positive on documentation content are suppressed when the match
    // falls inside a markdown code block.
    // Code block suppression in skill context:
    // - scan_target: 'skill' rules → NOT suppressed by default (their patterns
    //   are designed for SKILL.md code blocks which ARE executable instructions)
    // - skill rules with `tags.suppress_in_code_blocks: true` → suppressed
    //   (NL-style rules that should NOT match shell-command examples in pentest
    //   skills)
    // - Other rules → suppressed (their patterns FP on code examples)
    const isSkillCtx = event.scanContext === 'skill';
    const matchedRule = this.rules.find(r => r.id === ruleId);
    const isSkillRule = matchedRule?.tags?.scan_target === 'skill';
    const explicitSuppress = (matchedRule?.tags as { suppress_in_code_blocks?: boolean } | undefined)?.suppress_in_code_blocks === true;
    const suppressInCodeBlocks = explicitSuppress
      ? true
      : (isSkillCtx && !isSkillRule)
        ? true  // non-skill rules: always suppress code blocks in SKILL.md
        : (!isSkillCtx && this.shouldSuppressInCodeBlocks(ruleId));
    const codeRanges = suppressInCodeBlocks ? buildCodeBlockRanges(fieldValue) : [];

    // Get pre-compiled patterns
    const compiled = this.compiledPatterns.get(ruleId)?.get(condName);

    if (compiled) {
      for (let i = 0; i < compiled.length; i++) {
        if (safeRegexTest(compiled[i]!, fieldValue) || (rawFieldValue && safeRegexTest(compiled[i]!, rawFieldValue))) {
          // If match is inside a code block and this rule supports suppression, skip it
          if (suppressInCodeBlocks && codeRanges.length > 0 && isInsideCodeBlock(fieldValue, compiled[i]!, codeRanges)) {
            continue;
          }
          matchedPatterns.push(cond.patterns[i] ?? 'unknown');
          return true;
        }
      }
      return false;
    }

    // Fallback: direct string matching
    const checkValue = cond.case_sensitive ? fieldValue : fieldValue.toLowerCase();

    for (const pattern of cond.patterns) {
      const checkPattern = cond.case_sensitive ? pattern : pattern.toLowerCase();

      switch (cond.match_type) {
        case 'contains':
          if (checkValue.includes(checkPattern)) {
            matchedPatterns.push(pattern);
            return true;
          }
          break;
        case 'exact':
          if (checkValue === checkPattern) {
            matchedPatterns.push(pattern);
            return true;
          }
          break;
        case 'starts_with':
          if (checkValue.startsWith(checkPattern)) {
            matchedPatterns.push(pattern);
            return true;
          }
          break;
        case 'regex':
        default: {
          try {
            const flags = cond.case_sensitive ? '' : 'i';
            const regex = new RegExp(pattern, flags);
            if (safeRegexTest(regex, fieldValue)) {
              matchedPatterns.push(pattern);
              return true;
            }
          } catch {
            // Invalid regex, skip
          }
          break;
        }
      }
    }

    return false;
  }

  /**
   * Determine if a rule should suppress matches inside markdown code blocks.
   * Rules that commonly false-positive on documentation (shell commands, file paths,
   * code examples) are suppressed. Prompt injection rules are NEVER suppressed
   * because attackers deliberately hide payloads in code blocks.
   */
  private shouldSuppressInCodeBlocks(ruleId: string): boolean {
    const rule = this.rules.find(r => r.id === ruleId);
    if (!rule) return false;
    const category = rule.tags?.category ?? '';
    const subcategory = rule.tags?.subcategory ?? '';
    // Categories that commonly match documentation content
    const suppressCategories = [
      'privilege-escalation',  // ATR-111 shell metacharacter
      'context-exfiltration',  // ATR-113 credential paths
      'skill-compromise',      // supply chain patterns in docs
    ];
    // Never suppress skill-content rules (ATR-120+) — code blocks in SKILL.md
    // are executable instructions, not documentation examples
    const neverSuppressSubcategories = [
      'skill-instruction-injection',
      'dangerous-script',
      'weaponized-skill',
      'skill-overreach',
      'skill-squatting',
    ];
    if (neverSuppressSubcategories.includes(subcategory)) return false;
    return suppressCategories.includes(category);
  }

  /**
   * Evaluate a behavioral threshold condition.
   * When a session tracker is available and the event has a sessionId,
   * supports session-derived metrics: call_frequency, pattern_frequency, event_count.
   */
  private evaluateBehavioralCondition(
    cond: ATRBehavioralCondition,
    event: AgentEvent
  ): boolean {
    const metricValue = this.resolveMetricValue(cond, event);
    if (metricValue === undefined) return false;

    switch (cond.operator) {
      case 'gt': return metricValue > cond.threshold;
      case 'lt': return metricValue < cond.threshold;
      case 'eq': return metricValue === cond.threshold;
      case 'gte': return metricValue >= cond.threshold;
      case 'lte': return metricValue <= cond.threshold;
      case 'deviation_from_baseline':
        return Math.abs(metricValue) > cond.threshold;
      default:
        return false;
    }
  }

  /**
   * Resolve a metric value from event metrics or session tracker.
   * Session-derived metrics use the format: "call_frequency:toolName" or "pattern_frequency:pattern".
   */
  private resolveMetricValue(
    cond: ATRBehavioralCondition,
    event: AgentEvent
  ): number | undefined {
    // Check event-level metrics first
    const directValue = event.metrics?.[cond.metric];
    if (directValue !== undefined) return directValue;

    // Try session tracker for session-derived metrics
    const tracker = this.config.sessionTracker;
    const sessionId = event.sessionId;
    if (!tracker || !sessionId) return undefined;

    const windowMs = this.parseWindowMs(cond.window);

    if (cond.metric.startsWith('call_frequency:')) {
      const toolName = cond.metric.slice('call_frequency:'.length);
      return tracker.getCallFrequency(sessionId, toolName, windowMs);
    }

    if (cond.metric.startsWith('pattern_frequency:')) {
      const pattern = cond.metric.slice('pattern_frequency:'.length);
      return tracker.getPatternFrequency(sessionId, pattern, windowMs);
    }

    if (cond.metric === 'event_count') {
      return tracker.getEventCount(sessionId, windowMs);
    }

    return undefined;
  }

  /**
   * Parse a window string (e.g. "5m", "1h", "30s") to milliseconds.
   * Defaults to 5 minutes if not specified or unparseable.
   */
  private parseWindowMs(window: string | undefined): number {
    if (!window) return 5 * 60 * 1000;

    const match = window.match(/^(\d+)\s*(s|m|h)$/);
    if (!match) return 5 * 60 * 1000;

    const value = parseInt(match[1]!, 10);
    const unit = match[2]!;

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      default: return 5 * 60 * 1000;
    }
  }

  /**
   * Evaluate a sequence condition against the current event.
   *
   * Two modes:
   * 1. Session-aware (when SessionTracker + sessionId available):
   *    Checks patterns across historical events in the session.
   *    Respects `ordered` flag and `within` time window.
   * 2. Single-event fallback: checks if patterns co-occur in one event.
   */
  private evaluateSequenceCondition(
    cond: Record<string, unknown>,
    event: AgentEvent
  ): boolean {
    const steps = cond['steps'] as Array<Record<string, unknown>>;
    if (!steps || steps.length === 0) return false;

    // Try session-aware detection first
    const tracker = this.config.sessionTracker;
    const sessionId = event.sessionId;
    if (tracker && sessionId) {
      const sessionResult = this.evaluateSequenceAcrossSession(steps, cond, tracker, sessionId, event);
      if (sessionResult) return true;
    }

    // Fallback: single-event check
    return this.evaluateSequenceSingleEvent(steps, event);
  }

  /**
   * Cross-event sequence detection using SessionTracker.
   * Checks if step patterns have been seen across events in order.
   */
  private evaluateSequenceAcrossSession(
    steps: Array<Record<string, unknown>>,
    cond: Record<string, unknown>,
    tracker: SessionTracker,
    sessionId: string,
    currentEvent: AgentEvent
  ): boolean {
    const ordered = cond['ordered'] !== false; // default: true
    const withinMs = this.parseWindowMs(cond['within'] as string | undefined);
    const snapshot = tracker.getSessionSnapshot(sessionId);
    if (!snapshot) return false;

    // Collect all events: historical + current
    const allEvents = [...snapshot.events, currentEvent];
    if (allEvents.length < steps.length) return false;

    // For each step, find the earliest event that matches
    const stepMatches: Array<{ stepIndex: number; eventIndex: number; timestamp: number }> = [];

    for (let si = 0; si < steps.length; si++) {
      const step = steps[si]!;
      const patterns = step['patterns'] as string[] | undefined;
      if (!patterns) continue;

      for (let ei = 0; ei < allEvents.length; ei++) {
        const ev = allEvents[ei]!;
        const content = normalizeUnicode(ev.content);
        let matched = false;

        for (const pattern of patterns) {
          try {
            if (safeRegexTest(new RegExp(pattern, 'i'), content)) {
              matched = true;
              break;
            }
          } catch {
            // Invalid regex
          }
        }

        if (matched) {
          stepMatches.push({
            stepIndex: si,
            eventIndex: ei,
            timestamp: new Date(ev.timestamp).getTime(),
          });
          break; // First match per step
        }
      }
    }

    // Need all steps to match
    if (stepMatches.length < steps.length) return false;

    // Check ordering
    if (ordered) {
      for (let i = 1; i < stepMatches.length; i++) {
        if (stepMatches[i]!.eventIndex <= stepMatches[i - 1]!.eventIndex) {
          return false; // Out of order
        }
      }
    }

    // Check time window
    if (withinMs > 0) {
      const firstTs = Math.min(...stepMatches.map((m) => m.timestamp));
      const lastTs = Math.max(...stepMatches.map((m) => m.timestamp));
      if (lastTs - firstTs > withinMs) return false;
    }

    return true;
  }

  /**
   * Single-event fallback: check if step patterns co-occur in one event.
   */
  private evaluateSequenceSingleEvent(
    steps: Array<Record<string, unknown>>,
    event: AgentEvent
  ): boolean {
    const content = normalizeUnicode(event.content);
    let matchCount = 0;

    for (const step of steps) {
      const patterns = step['patterns'] as string[] | undefined;
      if (patterns) {
        for (const pattern of patterns) {
          try {
            if (safeRegexTest(new RegExp(pattern, 'i'), content)) {
              matchCount++;
              break;
            }
          } catch {
            // Invalid regex
          }
        }
      }
    }

    return matchCount >= 2;
  }

  // parseWindowMs already defined above (behavioral conditions)

  /**
   * Resolve a field value from an agent event.
   */
  private resolveField(fieldName: string, event: AgentEvent): string | undefined {
    // Skill context: a SKILL.md is the entire document. ALL fields resolve to
    // content so every rule can scan it. FP is controlled by requiring 2+
    // condition matches in skill context (see evaluate()), not by field filtering.
    if (event.scanContext === 'skill' && event.content) {
      return event.content;
    }

    // Check explicit fields first
    if (event.fields?.[fieldName]) {
      return event.fields[fieldName];
    }

    // Map standard field names to event properties
    const defaultField = EVENT_TYPE_TO_FIELD[event.type];
    if (fieldName === defaultField || fieldName === 'content') {
      return event.content;
    }

    // Common field aliases
    switch (fieldName) {
      case 'user_input':
        return event.type === 'llm_input' ? event.content : event.fields?.['user_input'];
      case 'agent_output':
        return event.type === 'llm_output' ? event.content : event.fields?.['agent_output'];
      case 'tool_response':
        return event.type === 'tool_response' ? event.content : event.fields?.['tool_response'];
      case 'tool_name':
        return event.fields?.['tool_name'] ?? (event.type === 'tool_call' ? event.content : undefined);
      case 'tool_args':
        return event.fields?.['tool_args'] ?? (event.type === 'tool_call' ? event.content : undefined);
      case 'agent_message':
        return event.type === 'multi_agent_message' ? event.content : event.fields?.['agent_message'];
      default:
        // Try metadata
        return event.metadata?.[fieldName] as string | undefined;
    }
  }

  /**
   * Evaluate a boolean expression string against condition results.
   * Supports AND, OR, NOT operators.
   */
  private evaluateExpression(
    expression: string,
    results: Map<string, boolean>
  ): boolean {
    const expr = expression.trim();

    // Simple single condition
    if (results.has(expr)) {
      return results.get(expr) ?? false;
    }

    // Handle NOT
    if (expr.startsWith('NOT ') || expr.startsWith('not ')) {
      const inner = expr.slice(4).trim();
      return !this.evaluateExpression(inner, results);
    }

    // Handle OR (lower precedence — split first so AND binds tighter)
    const orParts = this.splitByOperator(expr, 'OR');
    if (orParts.length > 1) {
      return orParts.some((part) => this.evaluateExpression(part, results));
    }

    // Handle AND (higher precedence — evaluated within each OR branch)
    const andParts = this.splitByOperator(expr, 'AND');
    if (andParts.length > 1) {
      return andParts.every((part) => this.evaluateExpression(part, results));
    }

    // Handle parentheses
    if (expr.startsWith('(') && expr.endsWith(')')) {
      return this.evaluateExpression(expr.slice(1, -1), results);
    }

    // Default: treat as condition name
    return results.get(expr) ?? false;
  }

  /**
   * Split expression by operator, respecting parentheses.
   */
  private splitByOperator(expr: string, operator: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let current = '';
    const op = ` ${operator} `;
    const opLower = ` ${operator.toLowerCase()} `;

    for (let i = 0; i < expr.length; i++) {
      const char = expr[i]!;
      if (char === '(') depth++;
      if (char === ')') depth--;

      if (depth === 0) {
        const remaining = expr.slice(i);
        if (remaining.startsWith(op) || remaining.startsWith(opLower)) {
          parts.push(current.trim());
          current = '';
          i += op.length - 1;
          continue;
        }
      }

      current += char;
    }

    if (current.trim()) {
      parts.push(current.trim());
    }

    return parts;
  }

  /**
   * Pre-compile regex patterns for a rule (performance optimization).
   * Supports both array-format and named-map-format conditions.
   */
  private compilePatterns(rule: ATRRule): void {
    const ruleMap = new Map<string, RegExp[]>();
    const conditions = rule.detection.conditions;

    if (Array.isArray(conditions)) {
      // Array format: compile each {operator: regex, value: "pattern"} entry
      for (let i = 0; i < conditions.length; i++) {
        const cond = conditions[i] as unknown as Record<string, unknown>;
        if (cond['operator'] === 'regex' && typeof cond['value'] === 'string') {
          try {
            const pattern = normalizeRegex(cond['value'] as string);
            const flags = pattern.includes('\\u{') || pattern.includes('\\p{') ? 'iu' : 'i';
            ruleMap.set(String(i), [new RegExp(pattern, flags)]);
          } catch {
            // Invalid regex, skip
          }
        }
      }
    } else {
      // Named format: compile patterns arrays
      for (const [condName, condDef] of Object.entries(conditions)) {
        const cond = condDef as unknown as Record<string, unknown>;
        if (cond['patterns'] && Array.isArray(cond['patterns'])) {
          const matchType = (cond['match_type'] as string) ?? 'regex';
          const caseSensitive = (cond['case_sensitive'] as boolean) ?? false;
          const flags = caseSensitive ? '' : 'i';

          const compiled: RegExp[] = [];
          for (const pattern of cond['patterns'] as string[]) {
            try {
              if (matchType === 'regex') {
                compiled.push(new RegExp(normalizeRegex(pattern), flags));
              } else if (matchType === 'contains') {
                compiled.push(new RegExp(escapeRegex(pattern), flags));
              } else if (matchType === 'exact') {
                compiled.push(new RegExp(`^${escapeRegex(pattern)}$`, flags));
              } else if (matchType === 'starts_with') {
                compiled.push(new RegExp(`^${escapeRegex(pattern)}`, flags));
              }
            } catch {
              // Invalid regex pattern, skip
            }
          }

          ruleMap.set(condName, compiled);
        }
      }
    }

    this.compiledPatterns.set(rule.id, ruleMap);
  }

  /**
   * Evaluate an event and compute a verdict with optional action execution.
   *
   * Combines evaluate() + computeVerdict() + optional ActionExecutor
   * into a single call for convenience.
   */
  async evaluateWithVerdict(
    event: AgentEvent,
    executor?: ActionExecutor
  ): Promise<{
    verdict: ATRVerdict;
    actionResults: readonly ActionResult[];
    layersUsed: readonly string[];
  }> {
    const layersUsed: string[] = ['layer1-regex'];
    let matches = this.evaluate(event);

    // Tier 0 + Tier 1 run inside evaluate(), track them
    if (this.config.invariantChecker) layersUsed.push('tier0-invariant');
    if (this.config.blacklistProvider) layersUsed.push('tier1-blacklist');

    // Layer 2 runs synchronously inside evaluate(), but track if it was configured
    if (this.config.fingerprintStore) {
      layersUsed.push('layer2-fingerprint');
    }

    // Tier 2.5: Embedding similarity (async, runs on all events)
    if (this.config.embeddingModule?.isAvailable()) {
      layersUsed.push('tier2.5-embedding');
      try {
        const embResult = await this.config.embeddingModule.evaluate(event, {
          module: 'embedding',
          function: 'similarity_search',
          args: { field: 'content' },
          operator: 'gte',
          threshold: 0.65,
        });

        if (embResult.matched) {
          const severity = embResult.value >= 0.95 ? 'critical' as const
            : embResult.value >= 0.88 ? 'high' as const
            : 'medium' as const;

          const syntheticMatch: ATRMatch = {
            rule: {
              title: `Embedding Match: ${embResult.description}`,
              id: 'tier2.5-embedding-match',
              status: 'experimental',
              description: embResult.description,
              author: 'atr-engine/tier2.5',
              date: new Date().toISOString().slice(0, 10),
              severity,
              tags: { category: 'prompt-injection', subcategory: 'semantic-similarity', confidence: 'high' },
              agent_source: { type: 'llm_io' },
              detection: { conditions: {}, condition: 'tier2.5-runtime' },
              response: {
                actions: severity === 'critical'
                  ? ['block_input', 'alert']
                  : ['alert'],
              },
            } as ATRRule,
            matchedConditions: ['embedding_similarity'],
            matchedPatterns: [`similarity=${embResult.value.toFixed(3)}`],
            confidence: embResult.value,
            timestamp: new Date().toISOString(),
            scan_context: 'native' as const,
          };
          matches = [...matches, syntheticMatch];
        }
      } catch {
        // Embedding failure is non-fatal
      }
    }

    // Layer 3: Semantic LLM-as-judge (async, conditional)
    if (this.semanticModuleInstance && shouldRunSemanticLayer(matches, event)) {
      layersUsed.push('layer3-semantic');
      const semanticMatches = await runSemanticLayer(
        this.semanticModuleInstance,
        event,
        matches,
      );
      if (semanticMatches.length > 0) {
        // Merge and re-sort immutably
        const merged = [...matches, ...semanticMatches];
        const severityOrder: Record<string, number> = {
          critical: 0, high: 1, medium: 2, low: 3, informational: 4,
        };
        merged.sort((a, b) => {
          const aSev = severityOrder[a.rule.severity] ?? 4;
          const bSev = severityOrder[b.rule.severity] ?? 4;
          if (aSev !== bSev) return aSev - bSev;
          return b.confidence - a.confidence;
        });
        matches = merged;
      }
    }

    const verdict = computeVerdict(matches);

    let actionResults: readonly ActionResult[] = Object.freeze([]);

    if (executor && verdict.actions.length > 0) {
      const context = Object.freeze({
        event,
        matches,
        verdict,
        sessionId: event.sessionId,
        metadata: event.metadata ? Object.freeze({ ...event.metadata }) : undefined,
      });
      actionResults = await executor.execute(context);
    }

    return { verdict, actionResults, layersUsed: Object.freeze(layersUsed) };
  }

  /** Get loaded rule count */
  getRuleCount(): number {
    return this.rules.length;
  }

  /** Get all loaded rules */
  getRules(): readonly ATRRule[] {
    return this.rules;
  }

  /** Get a rule by ID */
  getRuleById(id: string): ATRRule | undefined {
    return this.rules.find((r) => r.id === id);
  }

  /** Get rules by category */
  getRulesByCategory(category: string): ATRRule[] {
    return this.rules.filter((r) => r.tags.category === category);
  }

  /**
   * Scan SKILL.md content for threats.
   * All rules fire with scanContext='skill':
   *   - skill/both rules: native context, full confidence
   *   - MCP-only rules: cross-context, confidence * 0.6
   * Also decodes base64 blocks and scans decoded content.
   * Code-block suppression and FP denylist applied in evaluate().
   */
  scanSkill(content: string): ATRMatch[] {
    const baseEvent = {
      type: 'mcp_exchange' as const,
      timestamp: new Date().toISOString(),
      sessionId: 'skill-scan',
      fields: {},
      scanContext: 'skill' as const,
    };

    // Scan original content
    const matches = this.evaluate({ ...baseEvent, content });

    // Scan base64-decoded blocks for hidden payloads
    const decodedBlocks = decodeBase64Blocks(content);
    for (const block of decodedBlocks) {
      const blockMatches = this.evaluate({ ...baseEvent, content: block });
      for (const m of blockMatches) {
        // Tag decoded matches so consumers know the source
        matches.push({
          ...m,
          matchedPatterns: [...m.matchedPatterns, '[decoded:base64]'],
        });
      }
    }

    return matches;
  }

  /** Scan a SKILL.md file and return a unified ScanResult with content_hash. */
  scanSkillFull(content: string, filePath?: string): ScanResult {
    const matches = this.scanSkill(content);
    return {
      scan_type: 'skill',
      content_hash: computeContentHash(content),
      input_file: filePath,
      timestamp: new Date().toISOString(),
      rules_loaded: this.rules.length,
      matches,
      threat_count: matches.length,
    };
  }

  /** Evaluate an MCP agent event and return a unified ScanResult with content_hash. */
  evaluateFull(event: AgentEvent, filePath?: string): ScanResult {
    const matches = this.evaluate(event);
    // Hash content + fields to distinguish tool-call events with same content but different args
    const hashInput = event.fields
      ? event.content + '\0' + JSON.stringify(event.fields)
      : event.content;
    return {
      scan_type: 'mcp',
      content_hash: computeContentHash(hashInput),
      input_file: filePath,
      timestamp: new Date().toISOString(),
      rules_loaded: this.rules.length,
      matches,
      threat_count: matches.length,
    };
  }
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Strip inline flags like (?i) from regex patterns.
 * JavaScript RegExp uses flags as a constructor parameter, not inline.
 */
function normalizeRegex(pattern: string): string {
  return pattern.replace(/^\(\?[imsx]+\)/, '');
}

/**
 * Normalize Unicode text to NFC form and strip zero-width characters.
 * This prevents evasion via combining characters, zero-width joiners, etc.
 *
 * NFC was chosen over NFKC to preserve writer intent \u2014 full-width letters
 * (\uFF21\uFF22\uFF23 vs ABC) remain distinct so rules that explicitly target full-width
 * evasion can still match. For aggressive normalization use
 * `normalizeUnicodeAggressive()`.
 */
function normalizeUnicode(text: string): string {
  return text
    .normalize('NFC')
    .replace(/[\u200B\u200C\u200D\uFEFF\u2060\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '');
}

/**
 * Aggressive NFKC normalization for evasion-aware matching.
 *
 * NFKC collapses compatibility characters: full-width \uFF21\uFF22\uFF23 \u2192 ABC,
 * circled \u2460 \u2192 1, superscript \u00B2 \u2192 2. Use when a rule needs to match
 * regardless of presentational tricks. Always strips zero-width + bidi
 * override characters too.
 *
 * Currently invoked only via the v3.0 multilingual dispatch path for inputs
 * whose dominant script is non-Latin \u2014 full-width Latin in CJK text is a
 * known evasion vector.
 */
function normalizeUnicodeAggressive(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/[\u200B\u200C\u200D\uFEFF\u2060\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '');
}

/**
 * Heuristic dominant-script detection for v3.0 multilingual dispatch.
 *
 * Counts Unicode-block code points and returns the BCP-47 tag of the
 * dominant script. Used to skip language-tagged conditions whose
 * declared language does not match the input \u2014 pure optimisation, never
 * affects correctness of language-untagged rules.
 *
 * Disambiguation:
 *  - Han script: split via simplified-only vs traditional-only indicator
 *    char sets. Tie / both zero \u2192 defaults to 'zh-Hant'.
 *  - Latin script: 'es' if Spanish-specific punctuation/diacritics
 *    (\u00F1, \u00BF, \u00A1) detected, else 'en'.
 *  - Empty / pure ASCII without Spanish markers \u2192 'en'.
 *
 * Exported for unit testing; not part of the public API surface.
 */
export function detectInputLanguage(text: string): ATRLanguage {
  if (!text) return 'en';

  // Simplified-only common chars (rough but cheap).
  const SIMP_ONLY = /[\u56FD\u5B66\u65F6\u8FD9\u4EEC\u8BF4\u8BA9\u8BF7\u8FD0\u52A8\u6765\u4E2A\u4E07\u53D1\u5173\u73B0\u5B9E\u89C1\u4E49\u9F99\u4E1C\u8F66\u4E66]/;
  // Traditional-only common chars.
  const TRAD_ONLY = /[\u570B\u5B78\u6642\u9019\u5011\u8AAA\u8B93\u8ACB\u904B\u52D5\u4F86\u500B\u842C\u767C\u95DC\u73FE\u5BE6\u898B\u7FA9\u9F8D\u6771\u8ECA\u66F8]/;
  // Spanish-distinguishing characters.
  const ES_MARKER = /[\u00F1\u00D1\u00BF\u00A1\u00E1\u00E9\u00ED\u00F3\u00FA\u00FC\u00C1\u00C9\u00CD\u00D3\u00DA\u00DC]/;

  let han = 0;
  let hira = 0;
  let kata = 0;
  let arabic = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    if (cp >= 0x4e00 && cp <= 0x9fff) han++;
    else if (cp >= 0x3040 && cp <= 0x309f) hira++;
    else if (cp >= 0x30a0 && cp <= 0x30ff) kata++;
    else if (cp >= 0x0600 && cp <= 0x06ff) arabic++;
    else if (cp >= 0x0750 && cp <= 0x077f) arabic++; // Arabic supplement
    else if (cp >= 0xfb50 && cp <= 0xfdff) arabic++; // Arabic presentation A
    else if (cp >= 0xfe70 && cp <= 0xfeff) arabic++; // Arabic presentation B
  }

  if (arabic > 0) return 'ar';
  if (hira > 0 || kata > 0) return 'ja';
  if (han > 0) {
    const hasSimp = SIMP_ONLY.test(text);
    const hasTrad = TRAD_ONLY.test(text);
    if (hasSimp && !hasTrad) return 'zh-Hans';
    if (hasTrad && !hasSimp) return 'zh-Hant';
    // Tie or no disambiguation chars \u2192 default zh-Hant.
    // Downstream: callers should evaluate both zh-Hant and zh-Hans conditions
    // when this is the case (handled in conditionLanguageMatches below).
    return 'zh-Hant';
  }
  if (ES_MARKER.test(text)) return 'es';
  return 'en';
}

/**
 * Decide whether a condition with `language: condLang` should be evaluated
 * against an input whose detected language is `inputLang`.
 *
 * Rules:
 *  - condLang undefined (no language field) \u2192 always evaluate (v2.x compat)
 *  - condLang === inputLang \u2192 evaluate
 *  - Han-script ambiguity: if input is Han and condLang is the other
 *    Chinese variant, still evaluate (the cheap detector cannot reliably
 *    split zh-Hant vs zh-Hans, so we err on inclusion)
 *  - Otherwise \u2192 skip (return false)
 *
 * Exported for unit testing; not part of the public API surface.
 */
export function conditionLanguageMatches(
  condLang: ATRLanguage | undefined,
  inputLang: ATRLanguage
): boolean {
  if (condLang === undefined) return true;
  if (condLang === inputLang) return true;
  if (
    (condLang === 'zh-Hant' && inputLang === 'zh-Hans') ||
    (condLang === 'zh-Hans' && inputLang === 'zh-Hant')
  ) {
    return true;
  }
  return false;
}

/** Maximum input length for regex evaluation to mitigate ReDoS */
const MAX_EVAL_LENGTH = 100_000;

/**
 * Safely test a regex pattern against input with length limits.
 * Returns false if input exceeds MAX_EVAL_LENGTH to prevent ReDoS.
 */
function safeRegexTest(regex: RegExp, input: string): boolean {
  if (input.length > MAX_EVAL_LENGTH) return false;
  return regex.test(input);
}

/**
 * Build a set of character ranges that fall inside markdown code blocks.
 * Covers both fenced (``` ```) and inline (`code`) blocks.
 * Used to suppress false positives when regex matches documentation examples
 * rather than actual attack payloads.
 */
function buildCodeBlockRanges(text: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];

  // Fenced code blocks: parse line-by-line because ``` markers must alternate
  // open/close, which a simple non-greedy regex misaligns when the marker count
  // is odd or when prose contains stray triple-backticks.
  let blockStart: number | null = null;
  let pos = 0;
  const lines = text.split('\n');
  for (const line of lines) {
    const trimmed = line.trimStart();
    const isFence = trimmed.startsWith('```');
    if (isFence) {
      if (blockStart === null) {
        blockStart = pos;
      } else {
        ranges.push([blockStart, pos + line.length + 1]);
        blockStart = null;
      }
    }
    pos += line.length + 1; // +1 for the newline
  }
  if (blockStart !== null) {
    // Unterminated fence: treat from start to end of text as code
    ranges.push([blockStart, text.length]);
  }

  // Inline code: `...` (but not inside fenced blocks)
  const inline = /`[^`\n]+`/g;
  let m: RegExpExecArray | null;
  while ((m = inline.exec(text)) !== null) {
    const inlinePos = m.index;
    const inFenced = ranges.some(([start, end]) => inlinePos >= start && inlinePos < end);
    if (!inFenced) {
      ranges.push([inlinePos, inlinePos + m[0].length]);
    }
  }

  // Quoted strings inside markdown table rows: `| ... | "..." | ...`
  // Adversarial-example test cases in eval suites are commonly listed in
  // table cells as quoted attack payloads. Treat any "..." that appears on
  // a line beginning with `|` (markdown table) as suppressed code-equivalent.
  const tableLineRe = /^\|.*$/gm;
  while ((m = tableLineRe.exec(text)) !== null) {
    const lineStart = m.index;
    const line = m[0];
    // Find all "..." spans within the line and add as suppression ranges
    const quoteRe = /"[^"\n]+"/g;
    let qm: RegExpExecArray | null;
    while ((qm = quoteRe.exec(line)) !== null) {
      const absStart = lineStart + qm.index;
      ranges.push([absStart, absStart + qm[0].length]);
    }
  }

  return ranges;
}

/**
 * Check if a regex match position falls inside a code block.
 */
function isInsideCodeBlock(text: string, regex: RegExp, codeRanges: Array<[number, number]>): boolean {
  if (codeRanges.length === 0) return false;
  // Reset regex state and find match position
  const searchRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  const m = searchRegex.exec(text);
  if (!m) return false;
  const matchPos = m.index;
  return codeRanges.some(([start, end]) => matchPos >= start && matchPos < end);
}
