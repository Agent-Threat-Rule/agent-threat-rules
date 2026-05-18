/**
 * ATR (Agent Threat Rules) type definitions
 * @module agent-threat-rules/types
 */

export type ATRStatus = "draft" | "experimental" | "stable" | "deprecated";

export type ATRSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type ATRCategory =
  | "prompt-injection"
  | "tool-poisoning"
  | "context-exfiltration"
  | "agent-manipulation"
  | "privilege-escalation"
  | "excessive-autonomy"
  | "data-poisoning"
  | "model-abuse"
  | "skill-compromise";

export type ATRConfidence = "high" | "medium" | "low";

export type ATRSourceType =
  | "llm_io"
  | "tool_call"
  | "mcp_exchange"
  | "agent_behavior"
  | "multi_agent_comm"
  | "context_window"
  | "memory_access"
  | "skill_lifecycle"
  | "skill_permission"
  | "skill_chain";

export type ATRMatchType = "contains" | "regex" | "exact" | "starts_with";

/**
 * BCP-47 language tag used by multilingual rules (v3.0+).
 *
 * When a condition declares `language: 'zh-Hant'`, the engine will only
 * evaluate the condition against inputs whose dominant script matches.
 * Rules without an explicit `language` field default to `'en'` and apply
 * to all inputs (backwards-compatible with v2.x).
 *
 * Adding a new language: append the tag here and update
 * `detectInputLanguage()` in engine.ts to recognise the relevant Unicode
 * block.
 */
export type ATRLanguage =
  | "en"
  | "zh-Hant"
  | "zh-Hans"
  | "ja"
  | "es"
  | "ar";

export type ATROperator =
  | "gt"
  | "lt"
  | "eq"
  | "gte"
  | "lte"
  | "deviation_from_baseline";

export type ATRAction =
  | "block_input"
  | "block_output"
  | "block_tool"
  | "quarantine_session"
  | "reset_context"
  | "alert"
  | "shadow"
  | "snapshot"
  | "escalate"
  | "reduce_permissions"
  | "kill_agent";

export interface ATRReferences {
  owasp_llm?: string[];
  owasp_agentic?: string[];
  mitre_atlas?: string[];
  mitre_attack?: string[];
  cve?: string[];
}

export type ATRScanTarget = "mcp" | "skill" | "both" | "runtime";

export interface ATRTags {
  category: ATRCategory;
  subcategory?: string;
  confidence?: ATRConfidence;
  scan_target?: ATRScanTarget;
}

export interface ATRAgentSource {
  type: ATRSourceType;
  framework?: string[];
  provider?: string[];
}

export interface ATRPatternCondition {
  field: string;
  patterns: string[];
  match_type: ATRMatchType;
  case_sensitive?: boolean;
  /**
   * BCP-47 language tag. v3.0+ multilingual support.
   *
   * If set, this condition only fires when the engine's input language
   * detection matches. Default behaviour (field absent) is "match all
   * inputs", preserving v2.x compatibility.
   */
  language?: ATRLanguage;
}

export interface ATRBehavioralCondition {
  metric: string;
  operator: ATROperator;
  threshold: number;
  window?: string;
}

export interface ATRSequenceStep {
  field?: string;
  patterns?: string[];
  match_type?: ATRMatchType;
  metric?: string;
  operator?: ATROperator;
  threshold?: number;
}

export interface ATRSequenceCondition {
  ordered: boolean;
  within: string;
  steps: ATRSequenceStep[];
}

/** Array-format condition: {field, operator, value} used by most rules */
export interface ATRArrayCondition {
  field: string;
  operator: string;
  value: string;
  description?: string;
}

/** Named-map conditions or array conditions */
export type ATRConditions =
  | ATRArrayCondition[]
  | Record<
      string,
      ATRPatternCondition | ATRBehavioralCondition | ATRSequenceCondition
    >;

export interface ATRDetection {
  conditions: ATRConditions;
  /** "any" = OR across all conditions, "all" = AND. For named format: boolean expression string. */
  condition: string;
  false_positives?: string[];
}

export interface ATRResponse {
  actions: ATRAction[];
  auto_response_threshold?: string;
  message_template?: string;
}

export interface ATRTestCase {
  input?: string;
  tool_response?: string;
  agent_output?: string;
  tool_name?: string;
  tool_args?: string;
  expected: "trigger" | "no_trigger" | "triggered" | "not_triggered";
}

export interface ATRTestCases {
  true_positives: ATRTestCase[];
  true_negatives: ATRTestCase[];
}

export interface ATRRule {
  title: string;
  id: string;
  rule_version?: number;
  status: ATRStatus;
  description: string;
  author: string;
  date: string;
  modified?: string;
  schema_version?: string;
  detection_tier?: string;
  maturity?: string;
  severity: ATRSeverity;
  references?: ATRReferences;
  tags: ATRTags;
  agent_source: ATRAgentSource;
  detection: ATRDetection;
  response: ATRResponse;
  test_cases?: ATRTestCases;
  /** Evasion tests documenting known bypass techniques */
  evasion_tests?: ATREvasionTest[];
  /** Numeric confidence score (0-100), computed from precision + wild validation + evasion docs */
  confidence?: number;
  /** Date of last wild scan validation (YYYY/MM/DD format) */
  wild_validated?: string;
  /** Number of real-world samples tested in wild scan */
  wild_samples?: number;
  /** False positive rate measured on wild scan data (0.0 - 100.0) */
  wild_fp_rate?: number;
  /** Reason for deprecation (required when status is 'deprecated') */
  deprecated_reason?: string;
  /** ID of replacement rule (when status is 'deprecated') */
  replaced_by?: string;
}

export interface ATREvasionTest {
  input: string;
  expected: "triggered" | "not_triggered";
  bypass_technique: string;
  notes?: string;
}

/** Event types that the ATR engine can evaluate */
export type AgentEventType =
  | "llm_input"
  | "llm_output"
  | "tool_call"
  | "tool_response"
  | "agent_behavior"
  | "multi_agent_message"
  | "mcp_exchange";

/** An agent event to evaluate against ATR rules */
export interface AgentEvent {
  type: AgentEventType;
  timestamp: string;
  /** The text content to analyze */
  content: string;
  /** Specific field values for pattern matching */
  fields?: Record<string, string>;
  /** Behavioral metrics for threshold-based detection */
  metrics?: Record<string, number>;
  /** Session identifier for correlation */
  sessionId?: string;
  /** Source agent identifier */
  agentId?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Scan context: when 'skill', all rules fire regardless of agent_source.type,
   *  with cross-context confidence downweighting for MCP-only rules. */
  scanContext?: "mcp" | "skill";
}

/** Result when an ATR rule matches an event */
export type ScanContextType = "native" | "cross-context";

export interface ATRMatch {
  rule: ATRRule;
  matchedConditions: string[];
  matchedPatterns: string[];
  confidence: number;
  timestamp: string;
  /** Whether this match is native (rule designed for this scan path) or cross-context
   *  (e.g., MCP rule firing on SKILL.md content with confidence downweight). */
  scan_context: ScanContextType;
}

/** Verdict outcome from evaluating matched rules */
export type VerdictOutcome = "allow" | "ask" | "deny";

/** Verdict returned after evaluating an event against all rules */
export interface ATRVerdict {
  readonly outcome: VerdictOutcome;
  readonly reason: string;
  readonly matchCount: number;
  readonly highestSeverity: ATRSeverity | null;
  readonly highestConfidence: number;
  readonly actions: readonly ATRAction[];
  readonly matches: readonly ATRMatch[];
  readonly timestamp: string;
}

/** Result of executing a single action */
export interface ActionResult {
  readonly action: ATRAction;
  readonly success: boolean;
  readonly message: string;
  readonly timestamp: string;
}

/** Context provided to platform adapters when executing actions */
export interface ExecutionContext {
  readonly event: AgentEvent;
  readonly matches: readonly ATRMatch[];
  readonly verdict: ATRVerdict;
  readonly sessionId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/** Platform-specific adapter for executing ATR actions */
export interface PlatformAdapter {
  readonly name: string;
  blockInput(ctx: ExecutionContext): Promise<ActionResult>;
  blockOutput(ctx: ExecutionContext): Promise<ActionResult>;
  blockTool(ctx: ExecutionContext): Promise<ActionResult>;
  quarantineSession(ctx: ExecutionContext): Promise<ActionResult>;
  resetContext(ctx: ExecutionContext): Promise<ActionResult>;
  alert(ctx: ExecutionContext): Promise<ActionResult>;
  /**
   * Log the match for later audit without surfacing it to the user.
   * Used as the safe default for newly auto-generated rules
   * (CVE collector, probe pipeline, TC crystallisation) until they
   * accumulate FP-free production observation.
   */
  shadow(ctx: ExecutionContext): Promise<ActionResult>;
  snapshot(ctx: ExecutionContext): Promise<ActionResult>;
  escalate(ctx: ExecutionContext): Promise<ActionResult>;
  reducePermissions(ctx: ExecutionContext): Promise<ActionResult>;
  killAgent(ctx: ExecutionContext): Promise<ActionResult>;
}

/** Hook input from Claude Code / agent host */
export interface HookInput {
  readonly hook: "PreToolUse" | "PostToolUse";
  readonly tool_name: string;
  readonly tool_input: Readonly<Record<string, unknown>>;
  readonly session_id?: string;
  readonly timestamp?: string;
}

/** Hook output to Claude Code / agent host */
export interface HookOutput {
  readonly decision: VerdictOutcome;
  readonly reason?: string;
  readonly message?: string;
  readonly matched_rules?: readonly string[];
}

/** Scan type: MCP runtime event scan vs SKILL.md static file scan */
export type ScanType = "mcp" | "skill";

/** Unified scan result produced by both evaluate() and scanSkill() paths */
export interface ScanResult {
  readonly scan_type: ScanType;
  readonly content_hash: string;
  readonly input_file?: string;
  readonly timestamp: string;
  readonly rules_loaded: number;
  readonly matches: readonly ATRMatch[];
  readonly threat_count: number;
}
