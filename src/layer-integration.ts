/**
 * Layer Integration Helpers
 *
 * Bridges the ATREngine (Layer 1 regex) with:
 * - SkillFingerprintStore (Layer 2 behavioral fingerprinting)
 * - SemanticModule (Layer 3 LLM-as-judge)
 *
 * Extracted from engine.ts to keep file sizes manageable.
 *
 * @module agent-threat-rules/layer-integration
 */

import type { AgentEvent, ATRMatch, ATRRule, ATRSeverity } from './types.js';
import type { SkillFingerprintStore, BehaviorAnomaly } from './skill-fingerprint.js';
import type { SemanticModule, SemanticModuleConfig } from './modules/semantic.js';

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

/** Configuration for Layer 3 semantic analysis */
export interface SemanticLayerConfig {
  /** OpenAI-compatible API key */
  readonly apiKey: string;
  /** API base URL (default: https://api.openai.com) */
  readonly baseUrl?: string;
  /** Model identifier (default: gpt-4o-mini) */
  readonly model?: string;
}

// ---------------------------------------------------------------------------
// Layer 2: Skill Fingerprinting
// ---------------------------------------------------------------------------

/** Severity mapping for anomaly types */
const ANOMALY_SEVERITY_MAP: Readonly<Record<string, ATRSeverity>> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

/**
 * Resolve the skill identifier from an agent event.
 * Returns undefined if no skill identifier is present.
 */
export function resolveSkillId(event: AgentEvent): string | undefined {
  const fromMetadata = event.metadata?.['skill_id'];
  if (typeof fromMetadata === 'string' && fromMetadata.length > 0) {
    return fromMetadata;
  }

  const fromFields = event.fields?.['tool_name'];
  if (typeof fromFields === 'string' && fromFields.length > 0) {
    return fromFields;
  }

  return undefined;
}

/**
 * Create a synthetic ATRRule for a behavioral anomaly detected by Layer 2.
 * These rules are not loaded from YAML -- they are generated at runtime.
 */
function buildAnomalyRule(anomaly: BehaviorAnomaly): ATRRule {
  return {
    title: `Skill Behavior Drift: ${anomaly.anomalyType}`,
    id: `layer2-fingerprint-${anomaly.anomalyType}-${anomaly.skillName}`,
    status: 'experimental',
    // Explicit because src/verdict.ts caps a match's verdict by its maturity.
    // A behavioural-drift heuristic has no wild false-positive measurement, so
    // it may raise a question (`ask`) but must not auto-block on its own.
    maturity: 'test',
    description: anomaly.description,
    author: 'atr-engine/layer2',
    date: new Date(anomaly.timestamp).toISOString().slice(0, 10),
    severity: ANOMALY_SEVERITY_MAP[anomaly.severity] ?? 'medium',
    tags: {
      category: 'skill-compromise',
      subcategory: 'behavioral-drift',
      confidence: anomaly.severity === 'critical' ? 'high' : 'medium',
    },
    agent_source: { type: 'skill_lifecycle' },
    detection: {
      conditions: [],
      condition: 'layer2-runtime',
    },
    response: {
      actions: anomaly.severity === 'critical' ? ['alert', 'block_tool'] : ['alert'],
    },
  };
}

/**
 * Run Layer 2 fingerprint analysis on an event.
 * Returns additional ATRMatch entries for any detected anomalies.
 */
export function runFingerprintLayer(
  store: SkillFingerprintStore,
  event: AgentEvent,
  skillId: string,
): readonly ATRMatch[] {
  const anomalies = store.recordInvocation(skillId, event);

  if (anomalies.length === 0) {
    return [];
  }

  const matches: ATRMatch[] = [];
  for (const anomaly of anomalies) {
    const rule = buildAnomalyRule(anomaly);
    const confidence = anomaly.severity === 'critical'
      ? 0.95
      : anomaly.severity === 'high'
        ? 0.85
        : 0.7;

    matches.push({
      rule,
      matchedConditions: [anomaly.anomalyType],
      matchedPatterns: [anomaly.newValue],
      confidence,
      timestamp: new Date(anomaly.timestamp).toISOString(),
      scan_context: 'native' as const,
    });
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Layer 3: Semantic Analysis
// ---------------------------------------------------------------------------

/** Minimum severity rank that triggers Layer 3 analysis */
const SEMANTIC_TRIGGER_SEVERITIES: ReadonlySet<ATRSeverity> = new Set([
  'medium',
  'high',
  'critical',
]);

/**
 * Determine whether Layer 3 semantic analysis should run.
 *
 * Triggers when:
 * - Any Layer 1/2 match has medium or higher severity
 * - The event explicitly requests deep analysis via metadata
 */
export function shouldRunSemanticLayer(
  layer1Matches: readonly ATRMatch[],
  event: AgentEvent,
): boolean {
  // Explicit opt-in via metadata
  if (event.metadata?.['force_semantic'] === true) {
    return true;
  }

  // Check if any existing matches have medium+ severity
  for (const match of layer1Matches) {
    if (SEMANTIC_TRIGGER_SEVERITIES.has(match.rule.severity)) {
      return true;
    }
  }

  return false;
}

/**
 * Create a SemanticModule instance from simplified config.
 * Returns undefined if the semantic module cannot be imported.
 */
export function createSemanticModuleFromConfig(
  config: SemanticLayerConfig,
): SemanticModuleConfig {
  return {
    apiUrl: config.baseUrl ?? 'https://api.openai.com',
    apiKey: config.apiKey,
    model: config.model ?? 'gpt-4o-mini',
  };
}

/**
 * Run Layer 3 semantic analysis and return upgraded/new matches.
 *
 * The semantic module is called with `analyze_threat` to get a threat score.
 * If the score is >= 0.7, a synthetic high-severity match is produced.
 * If the score is 0.4-0.7, existing matches may have confidence boosted.
 */
export async function runSemanticLayer(
  semanticModule: SemanticModule,
  event: AgentEvent,
  existingMatches: readonly ATRMatch[],
): Promise<readonly ATRMatch[]> {
  const result = await semanticModule.evaluate(event, {
    module: 'semantic',
    function: 'analyze_threat',
    args: { field: 'content' },
    operator: 'gte',
    threshold: 0.4,
  });

  if (!result.matched) {
    return [];
  }

  const additionalMatches: ATRMatch[] = [];

  // High threat score: create a new synthetic match
  if (result.value >= 0.7) {
    const syntheticRule: ATRRule = {
      title: 'Semantic Threat Detected (Layer 3)',
      id: 'layer3-semantic-threat',
      status: 'experimental',
      // Explicit because src/verdict.ts caps a match's verdict by its maturity.
      // An LLM judge's score is unmeasured against any benign corpus, so this
      // synthetic match may interrupt for a human decision (`ask`) but is not
      // allowed to auto-block by itself. BEHAVIOUR CHANGE: before the maturity
      // cap, a threat_score >= 0.9 produced `deny` here.
      maturity: 'test',
      description: result.description,
      author: 'atr-engine/layer3',
      date: new Date().toISOString().slice(0, 10),
      severity: result.value >= 0.9 ? 'critical' : 'high',
      tags: {
        category: 'prompt-injection',
        subcategory: 'semantic-detection',
        confidence: 'high',
      },
      agent_source: { type: 'llm_io' },
      detection: {
        conditions: [],
        condition: 'layer3-runtime',
      },
      response: {
        actions: result.value >= 0.9 ? ['block_input', 'alert'] : ['alert'],
      },
    };

    additionalMatches.push({
      rule: syntheticRule,
      matchedConditions: ['semantic_analysis'],
      matchedPatterns: [`threat_score=${result.value.toFixed(2)}`],
      confidence: result.value,
      timestamp: new Date().toISOString(),
      scan_context: 'native' as const,
    });
  }

  return additionalMatches;
}
