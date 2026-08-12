/**
 * Verdict computation tests.
 *
 * Validates computeVerdict(), isAutoResponseEnabled(), and SEVERITY_RANK
 * from the verdict module.
 */

import { describe, it, expect } from 'vitest';
import { computeVerdict, isAutoResponseEnabled, SEVERITY_RANK } from '../src/verdict.js';
import type { ATRMatch, ATRRule, ATRSeverity } from '../src/types.js';

/**
 * Build a minimal ATRRule with the given severity and actions.
 *
 * `maturity` defaults to `stable` because these cases exercise the
 * severity/confidence matrix, and since the verdict is also capped by maturity
 * (see tests/verdict-maturity.test.ts) a fixture that left the field unset
 * would silently be testing the ceiling instead of the matrix.
 */
function makeRule(overrides: {
  id?: string;
  severity?: ATRSeverity;
  maturity?: string;
  actions?: string[];
  auto_response_threshold?: string;
  title?: string;
}): ATRRule {
  return {
    id: overrides.id ?? 'TEST-001',
    title: overrides.title ?? 'Test Rule',
    status: 'stable',
    maturity: overrides.maturity ?? 'stable',
    description: 'A test rule',
    author: 'test',
    date: '2026-01-01',
    severity: overrides.severity ?? 'medium',
    tags: { category: 'prompt-injection' },
    agent_source: { type: 'llm_io' },
    detection: {
      conditions: [],
      condition: 'any',
    },
    response: {
      actions: (overrides.actions ?? ['alert']) as ATRRule['response']['actions'],
      auto_response_threshold: overrides.auto_response_threshold,
    },
  } as ATRRule;
}

/** Build a minimal ATRMatch for a given rule and confidence */
function makeMatch(rule: ATRRule, confidence: number): ATRMatch {
  return {
    rule,
    matchedConditions: ['0'],
    matchedPatterns: ['test_pattern'],
    confidence,
    timestamp: new Date().toISOString(),
  };
}

describe('SEVERITY_RANK', () => {
  it('has correct numeric ordering for all 5 severities', () => {
    expect(SEVERITY_RANK.critical).toBe(0);
    expect(SEVERITY_RANK.high).toBe(1);
    expect(SEVERITY_RANK.medium).toBe(2);
    expect(SEVERITY_RANK.low).toBe(3);
    expect(SEVERITY_RANK.informational).toBe(4);
  });

  it('is Readonly at the type level (not writable in TypeScript)', () => {
    // SEVERITY_RANK uses Readonly<Record<...>> which enforces
    // compile-time immutability. Runtime freezing is not applied,
    // but the values should remain stable.
    expect(Object.keys(SEVERITY_RANK)).toHaveLength(5);
  });
});

describe('computeVerdict', () => {
  it('returns allow with empty actions when no matches', () => {
    const verdict = computeVerdict([]);

    expect(verdict.outcome).toBe('allow');
    expect(verdict.matchCount).toBe(0);
    expect(verdict.highestSeverity).toBeNull();
    expect(verdict.highestConfidence).toBe(0);
    expect(verdict.actions).toHaveLength(0);
    expect(verdict.matches).toHaveLength(0);
    expect(verdict.reason).toBe('No rules matched.');
  });

  it('returns deny for a single critical match', () => {
    const rule = makeRule({ severity: 'critical' });
    const match = makeMatch(rule, 0.95);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('deny');
    expect(verdict.highestSeverity).toBe('critical');
    expect(verdict.matchCount).toBe(1);
  });

  it('returns deny for high severity with confidence >= 0.8', () => {
    const rule = makeRule({ severity: 'high' });
    const match = makeMatch(rule, 0.85);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('deny');
    expect(verdict.highestSeverity).toBe('high');
  });

  it('returns ask for high severity with confidence < 0.8', () => {
    const rule = makeRule({ severity: 'high' });
    const match = makeMatch(rule, 0.7);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('ask');
    expect(verdict.highestSeverity).toBe('high');
  });

  it('returns ask for medium severity with confidence >= 0.6', () => {
    const rule = makeRule({ severity: 'medium' });
    const match = makeMatch(rule, 0.65);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('ask');
    expect(verdict.highestSeverity).toBe('medium');
  });

  it('returns allow for medium severity with confidence < 0.6', () => {
    const rule = makeRule({ severity: 'medium' });
    const match = makeMatch(rule, 0.5);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('allow');
  });

  it('returns allow for a single low severity match', () => {
    const rule = makeRule({ severity: 'low' });
    const match = makeMatch(rule, 0.9);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('allow');
  });

  it('returns allow for a single informational severity match', () => {
    const rule = makeRule({ severity: 'informational' });
    const match = makeMatch(rule, 0.99);

    const verdict = computeVerdict([match]);

    expect(verdict.outcome).toBe('allow');
  });

  it('highest severity wins when multiple matches are present', () => {
    // Engine sorts matches by severity desc, so critical comes first
    const criticalRule = makeRule({ id: 'CRIT-001', severity: 'critical' });
    const lowRule = makeRule({ id: 'LOW-001', severity: 'low' });

    const matches = [
      makeMatch(criticalRule, 0.95), // first = highest severity
      makeMatch(lowRule, 0.5),
    ];

    const verdict = computeVerdict(matches);

    expect(verdict.outcome).toBe('deny');
    expect(verdict.highestSeverity).toBe('critical');
    expect(verdict.matchCount).toBe(2);
  });

  it('collects and deduplicates actions from all matches', () => {
    const rule1 = makeRule({
      id: 'R1',
      severity: 'critical',
      actions: ['alert', 'block_input', 'snapshot'],
    });
    const rule2 = makeRule({
      id: 'R2',
      severity: 'high',
      actions: ['alert', 'escalate'], // 'alert' is a duplicate
    });

    const matches = [
      makeMatch(rule1, 0.95),
      makeMatch(rule2, 0.85),
    ];

    const verdict = computeVerdict(matches);

    // alert should appear only once
    const alertCount = verdict.actions.filter((a) => a === 'alert').length;
    expect(alertCount).toBe(1);

    // all unique actions should be present
    expect(verdict.actions).toContain('alert');
    expect(verdict.actions).toContain('block_input');
    expect(verdict.actions).toContain('snapshot');
    expect(verdict.actions).toContain('escalate');
    expect(verdict.actions).toHaveLength(4);
  });

  it('reason string contains highest severity rule info', () => {
    const rule = makeRule({
      severity: 'critical',
      title: 'Critical Injection Attack',
    });
    const match = makeMatch(rule, 0.95);

    const verdict = computeVerdict([match]);

    expect(verdict.reason).toContain('DENY');
    expect(verdict.reason).toContain('Critical Injection Attack');
    expect(verdict.reason).toContain('critical');
    expect(verdict.reason).toContain('95%');
    expect(verdict.reason).toContain('1 rule matched');
  });

  it('reason string uses plural for multiple matches', () => {
    const rule1 = makeRule({ id: 'R1', severity: 'critical' });
    const rule2 = makeRule({ id: 'R2', severity: 'high' });

    const verdict = computeVerdict([
      makeMatch(rule1, 0.9),
      makeMatch(rule2, 0.8),
    ]);

    expect(verdict.reason).toContain('2 rules matched');
  });

  it('timestamp is a valid ISO string', () => {
    const verdict = computeVerdict([]);
    const parsed = new Date(verdict.timestamp);
    expect(parsed.toISOString()).toBe(verdict.timestamp);
  });

  it('returns a frozen verdict object', () => {
    const verdict = computeVerdict([]);
    expect(Object.isFrozen(verdict)).toBe(true);
  });

  it('returns frozen actions array', () => {
    const rule = makeRule({ severity: 'critical', actions: ['alert'] });
    const verdict = computeVerdict([makeMatch(rule, 0.9)]);
    expect(Object.isFrozen(verdict.actions)).toBe(true);
  });

  it('returns frozen matches array', () => {
    const rule = makeRule({ severity: 'critical' });
    const verdict = computeVerdict([makeMatch(rule, 0.9)]);
    expect(Object.isFrozen(verdict.matches)).toBe(true);
  });
});

describe('isAutoResponseEnabled', () => {
  it('returns true when threshold matches severity and confidence is sufficient', () => {
    // threshold "high" requires confidence >= 0.9
    const rule = makeRule({ auto_response_threshold: 'high' });
    const match = makeMatch(rule, 0.95);

    expect(isAutoResponseEnabled(match)).toBe(true);
  });

  it('returns true for medium threshold with confidence >= 0.7', () => {
    const rule = makeRule({ auto_response_threshold: 'medium' });
    const match = makeMatch(rule, 0.75);

    expect(isAutoResponseEnabled(match)).toBe(true);
  });

  it('returns true for low threshold with confidence >= 0.5', () => {
    const rule = makeRule({ auto_response_threshold: 'low' });
    const match = makeMatch(rule, 0.5);

    expect(isAutoResponseEnabled(match)).toBe(true);
  });

  it('returns false when confidence is below threshold', () => {
    // threshold "high" requires confidence >= 0.9
    const rule = makeRule({ auto_response_threshold: 'high' });
    const match = makeMatch(rule, 0.85);

    expect(isAutoResponseEnabled(match)).toBe(false);
  });

  it('returns false when response has no auto_response_threshold', () => {
    const rule = makeRule({ auto_response_threshold: undefined });
    const match = makeMatch(rule, 0.99);

    expect(isAutoResponseEnabled(match)).toBe(false);
  });

  it('returns false for unknown threshold value', () => {
    const rule = makeRule({ auto_response_threshold: 'unknown_value' });
    const match = makeMatch(rule, 0.99);

    expect(isAutoResponseEnabled(match)).toBe(false);
  });
});
