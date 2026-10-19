/**
 * Shadow Evaluator -- runs experimental rules without affecting verdict.
 *
 * Experimental rules evaluate against every event but don't influence
 * the real verdict. Their match/no-match results are tracked to measure
 * false positive rates. Rules with FP < threshold get promoted.
 *
 * @module agent-threat-rules/shadow-evaluator
 */

import type { ATRRule, ATRMatch, AgentEvent } from './types.js';

interface ShadowRuleStats {
  readonly ruleId: string;
  totalEvaluations: number;
  totalMatches: number;
  confirmedTruePositives: number;
  confirmedFalsePositives: number;
  firstSeen: number;
  lastSeen: number;
}

export interface PromotionCandidate {
  readonly rule: ATRRule;
  readonly stats: Readonly<ShadowRuleStats>;
  readonly fpRate: number;
}

export class ShadowEvaluator {
  private readonly rules: ATRRule[] = [];
  private readonly stats = new Map<string, ShadowRuleStats>();
  private readonly compiledPatterns = new Map<string, RegExp>();

  /** Add an experimental rule for shadow evaluation */
  addRule(rule: ATRRule): void {
    if (this.rules.some((r) => r.id === rule.id)) return; // dedup
    this.rules.push(rule);
    this.stats.set(rule.id, {
      ruleId: rule.id,
      totalEvaluations: 0,
      totalMatches: 0,
      confirmedTruePositives: 0,
      confirmedFalsePositives: 0,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
    });
  }

  /** Evaluate all shadow rules against an event (does NOT affect verdict) */
  evaluate(event: AgentEvent): readonly ATRMatch[] {
    const matches: ATRMatch[] = [];

    for (const rule of this.rules) {
      const stat = this.stats.get(rule.id);
      if (!stat) continue;

      stat.totalEvaluations++;
      stat.lastSeen = Date.now();

      // Simple regex evaluation for shadow rules
      const detection = rule.detection;
      const conditions = Array.isArray(detection.conditions)
        ? detection.conditions
        : Object.values(detection.conditions);

      let matched = false;
      for (const cond of conditions) {
        const c = cond as unknown as Record<string, unknown>;
        const value = c['value'] as string;
        const field = c['field'] as string;
        if (!value || !field) continue;

        const text = event.fields?.[field] ?? event.content ?? '';
        try {
          let regex = this.compiledPatterns.get(value);
          if (!regex) {
            regex = new RegExp(value, 'i');
            this.compiledPatterns.set(value, regex);
          }
          if (regex.test(text)) {
            matched = true;
            break;
          }
        } catch {
          // Invalid regex
        }
      }

      if (matched) {
        stat.totalMatches++;
        matches.push({
          rule,
          matchedConditions: ['shadow'],
          matchedPatterns: ['shadow-match'],
          confidence: 0.5, // Shadow matches have reduced confidence
          timestamp: new Date().toISOString(),
          scan_context: 'native' as const,
          decidedBy: 'pattern' as const,
        });
      }
    }

    return matches;
  }

  /** Record user feedback on a shadow match */
  recordFeedback(ruleId: string, isTruePositive: boolean): void {
    const stat = this.stats.get(ruleId);
    if (!stat) return;
    if (isTruePositive) {
      stat.confirmedTruePositives++;
    } else {
      stat.confirmedFalsePositives++;
    }
  }

  /**
   * Get rules ready for promotion.
   * Criteria: FP rate < maxFPRate AND minimum evaluations reached.
   */
  getPromotionCandidates(
    maxFPRate: number = 0.001,
    minEvaluations: number = 1000
  ): readonly PromotionCandidate[] {
    const candidates: PromotionCandidate[] = [];

    for (const rule of this.rules) {
      const stat = this.stats.get(rule.id);
      if (!stat || stat.totalEvaluations < minEvaluations) continue;

      const fpRate = stat.totalMatches > 0
        ? stat.confirmedFalsePositives / stat.totalMatches
        : 0;

      // Only promote if:
      // 1. Has been evaluated enough times
      // 2. FP rate is below threshold
      // 3. Has at least some matches (not a dead rule)
      if (fpRate <= maxFPRate && stat.totalMatches > 0) {
        candidates.push({ rule, stats: { ...stat }, fpRate });
      }
    }

    return candidates;
  }

  /** Get stats for a specific rule */
  getStats(ruleId: string): Readonly<ShadowRuleStats> | undefined {
    const stat = this.stats.get(ruleId);
    return stat ? { ...stat } : undefined;
  }

  /** Get all shadow rule stats */
  getAllStats(): ReadonlyMap<string, Readonly<ShadowRuleStats>> {
    return new Map(Array.from(this.stats.entries()).map(([k, v]) => [k, { ...v }]));
  }

  /** Number of shadow rules */
  size(): number {
    return this.rules.length;
  }
}
