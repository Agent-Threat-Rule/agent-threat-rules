/**
 * Flywheel Manager -- automates the threat detection → rule generation → promotion cycle.
 *
 * Flow:
 * 1. Tier 4 (LLM) detects novel threat → auto-scaffold rule
 * 2. Rule enters shadow mode → ShadowEvaluator tracks FP rate
 * 3. FP < threshold after N evaluations → auto-promote to stable
 * 4. Promoted rule distributes to all users via Threat Cloud
 *
 * Machine speed, not human speed. No manual proposals or voting required.
 *
 * @module agent-threat-rules/flywheel
 */

import type { ATRRule, ATRMatch, AgentEvent } from './types.js';
import { RuleScaffolder, type ScaffoldInput } from './rule-scaffolder.js';
import { ShadowEvaluator, type PromotionCandidate } from './shadow-evaluator.js';

export interface FlywheelConfig {
  /** Max FP rate for auto-promotion (default: 0.001 = 0.1%) */
  readonly maxFPRate?: number;
  /** Minimum shadow evaluations before promotion (default: 1000) */
  readonly minEvaluations?: number;
  /** Minimum matches with recorded feedback before promotion (default: 1; unreviewed matches never count) */
  readonly minReviewedMatches?: number;
  /** Callback when a rule is auto-promoted */
  readonly onPromote?: (rule: ATRRule, stats: PromotionCandidate['stats']) => void | Promise<void>;
  /** Callback when a new shadow rule is generated */
  readonly onShadowRule?: (rule: ATRRule) => void | Promise<void>;
}

export class FlywheelManager {
  private readonly scaffolder: RuleScaffolder;
  private readonly shadow: ShadowEvaluator;
  private readonly config: Required<FlywheelConfig>;
  private readonly existingIds = new Set<string>();
  /** Rules already handed to onPromote, so a periodic promoteReady() does not promote them again. */
  private readonly promotedIds = new Set<string>();

  constructor(config: FlywheelConfig = {}) {
    this.scaffolder = new RuleScaffolder({ author: 'ATR Flywheel (auto-generated)' });
    this.shadow = new ShadowEvaluator();
    this.config = {
      maxFPRate: config.maxFPRate ?? 0.001,
      minEvaluations: config.minEvaluations ?? 1000,
      minReviewedMatches: config.minReviewedMatches ?? 1,
      onPromote: config.onPromote ?? (() => {}),
      onShadowRule: config.onShadowRule ?? (() => {}),
    };
  }

  /**
   * Called when Tier 4 (LLM semantic) detects a novel threat.
   * Auto-generates a shadow rule from the detection.
   */
  async onTier4Detection(match: ATRMatch, event: AgentEvent): Promise<ATRRule | null> {
    // Only generate from high-confidence Tier 4 matches
    if (match.confidence < 0.7) return null;

    // Extract category and severity from the match
    const category = match.rule.tags?.category ?? 'prompt-injection';
    const severity = match.rule.severity ?? 'medium';

    // Build example payloads from ATTACK PATTERNS, not just raw content.
    // Priority: matched patterns > event fields > event content
    const payloads: string[] = [];

    // 1. Matched patterns from the Tier 4 detection — these ARE the attack signals
    if (match.matchedPatterns.length > 0) {
      payloads.push(...match.matchedPatterns.filter((p) => p.trim().length > 5));
    }

    // 2. Event fields (tool_args, tool_response, etc.) — more specific than content
    if (event.fields) {
      for (const value of Object.values(event.fields)) {
        if (value && value.trim().length > 10) {
          payloads.push(value.slice(0, 500));
        }
      }
    }

    // 3. Event content as fallback — but only if we don't have better signals
    if (payloads.length === 0 && event.content) {
      payloads.push(event.content.slice(0, 500));
    }

    // Ensure at least one payload
    if (payloads.length === 0) {
      payloads.push(match.rule.description ?? match.rule.title);
    }

    const input: ScaffoldInput = {
      title: `Auto: ${match.rule.description?.slice(0, 60) ?? match.rule.title}`,
      category: category as ScaffoldInput['category'],
      severity: severity as ScaffoldInput['severity'],
      attackDescription: match.rule.description ?? match.matchedPatterns.join('; '),
      examplePayloads: payloads,
    };

    try {
      const result = this.scaffolder.scaffold(input, this.existingIds);
      const ruleYaml = result.yaml;

      // Parse back to ATRRule object
      const { default: yaml } = await import('js-yaml');
      const rule = yaml.load(ruleYaml) as ATRRule;
      rule.status = 'experimental';

      this.existingIds.add(result.id);
      this.shadow.addRule(rule);

      await this.config.onShadowRule(rule);

      return rule;
    } catch {
      return null;
    }
  }

  /**
   * Called for every event -- runs shadow evaluation.
   * Returns shadow matches (for logging only, not verdict).
   */
  evaluateShadow(event: AgentEvent): readonly ATRMatch[] {
    return this.shadow.evaluate(event);
  }

  /** Record user feedback on a shadow match */
  recordFeedback(ruleId: string, isTruePositive: boolean): void {
    this.shadow.recordFeedback(ruleId, isTruePositive);
  }

  /**
   * Check for rules ready to promote and execute promotion.
   * Call periodically (e.g., every 15 minutes).
   */
  async promoteReady(): Promise<readonly PromotionCandidate[]> {
    const candidates = this.shadow
      .getPromotionCandidates(this.config.maxFPRate, this.config.minEvaluations, this.config.minReviewedMatches)
      .filter((candidate) => !this.promotedIds.has(candidate.rule.id));

    for (const candidate of candidates) {
      // Promote: change status from experimental to stable. maturity stays
      // 'draft', so ATREngine's lane gate still keeps the rule out of the
      // enforce and alert lanes until it passes canPromote().
      const promoted = { ...candidate.rule, status: 'stable' as const };
      await this.config.onPromote(promoted, candidate.stats);
      this.promotedIds.add(candidate.rule.id);
    }

    return candidates;
  }

  /** Get shadow evaluator stats */
  getShadowStats(): ReadonlyMap<string, unknown> {
    return this.shadow.getAllStats();
  }

  /** Number of rules in shadow mode */
  shadowRuleCount(): number {
    return this.shadow.size();
  }
}
