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
} from './types.js';
import { loadRulesFromDirectory, loadRuleFile } from './loader.js';
import type { SessionTracker } from './session-tracker.js';

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

export interface ATREngineConfig {
  /** Directory containing ATR rule YAML files */
  rulesDir?: string;
  /** Pre-loaded rules (for testing or embedding) */
  rules?: ATRRule[];
  /** Enable hot-reload of rule files */
  hotReload?: boolean;
  /** Optional session tracker for behavioral detection across events */
  sessionTracker?: SessionTracker;
}

export class ATREngine {
  private rules: ATRRule[] = [];
  private readonly compiledPatterns = new Map<string, Map<string, RegExp[]>>();

  constructor(private readonly config: ATREngineConfig = {}) {}

  /**
   * Load rules from configured directory and/or pre-loaded rules.
   */
  async loadRules(): Promise<number> {
    this.rules = [];
    this.compiledPatterns.clear();

    if (this.config.rules) {
      this.rules.push(...this.config.rules);
    }

    if (this.config.rulesDir) {
      try {
        const fileRules = loadRulesFromDirectory(this.config.rulesDir);
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

    for (const rule of this.rules) {
      // Skip deprecated and draft rules
      if (rule.status === 'deprecated' || rule.status === 'draft') continue;

      // Source type filtering: skip rules that don't apply to this event type
      if (eventSourceType && rule.agent_source.type !== eventSourceType) {
        // Allow mcp_exchange rules to also match tool_call events
        if (!(rule.agent_source.type === 'mcp_exchange' && eventSourceType === 'tool_call')) {
          continue;
        }
      }

      const matchResult = this.evaluateRule(rule, event);
      if (matchResult) {
        matches.push(matchResult);
        allMatchedPatterns.push(...matchResult.matchedPatterns);
      }
    }

    // Record the event in the session tracker if available
    const sessionId = event.sessionId;
    if (this.config.sessionTracker && sessionId) {
      this.config.sessionTracker.recordEvent(sessionId, event, allMatchedPatterns);
    }

    // Sort by severity (critical first) then confidence
    return matches.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
      const aSev = severityOrder[a.rule.severity] ?? 4;
      const bSev = severityOrder[b.rule.severity] ?? 4;
      if (aSev !== bSev) return aSev - bSev;
      return b.confidence - a.confidence;
    });
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
    const field = cond['field'] as string | undefined;
    const operator = cond['operator'] as string | undefined;
    const value = cond['value'] as string | undefined;

    if (!field || !operator || value === undefined) return false;

    const rawFieldValue = this.resolveField(field, event);
    if (!rawFieldValue) return false;
    const fieldValue = normalizeUnicode(rawFieldValue);

    switch (operator) {
      case 'regex': {
        // Try pre-compiled pattern first
        const compiled = this.compiledPatterns.get(ruleId)?.get(String(index));
        if (compiled && compiled.length > 0) {
          if (safeRegexTest(compiled[0]!, fieldValue)) {
            matchedPatterns.push(value);
            return true;
          }
          return false;
        }
        // Fallback: compile on the fly
        try {
          const regex = new RegExp(normalizeRegex(value), 'i');
          if (safeRegexTest(regex, fieldValue)) {
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

    // Get pre-compiled patterns
    const compiled = this.compiledPatterns.get(ruleId)?.get(condName);

    if (compiled) {
      for (let i = 0; i < compiled.length; i++) {
        if (safeRegexTest(compiled[i]!, fieldValue)) {
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
   * Limitation (v0.1): This checks whether patterns from multiple steps
   * co-occur in the current event's content. It does NOT track ordered
   * execution across separate events or enforce time windows.
   * Full session-aware sequence detection is planned for v0.2.
   */
  private evaluateSequenceCondition(
    cond: Record<string, unknown>,
    event: AgentEvent
  ): boolean {
    const steps = cond['steps'] as Array<Record<string, unknown>>;
    if (!steps || steps.length === 0) return false;

    const content = normalizeUnicode(event.content);
    let matchCount = 0;

    for (const step of steps) {
      const patterns = step['patterns'] as string[] | undefined;
      if (patterns) {
        for (const pattern of patterns) {
          try {
            const regex = new RegExp(pattern, 'i');
            if (safeRegexTest(regex, content)) {
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

  /**
   * Resolve a field value from an agent event.
   */
  private resolveField(fieldName: string, event: AgentEvent): string | undefined {
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
        return event.fields?.['tool_args'];
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
            ruleMap.set(String(i), [new RegExp(normalizeRegex(cond['value'] as string), 'i')]);
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
 */
function normalizeUnicode(text: string): string {
  return text
    .normalize('NFC')
    .replace(/[\u200B\u200C\u200D\uFEFF\u2060\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '');
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
