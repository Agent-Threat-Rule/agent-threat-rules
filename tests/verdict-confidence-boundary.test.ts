/**
 * The verdict for a pattern match must not depend on how 0.7 + 0.1 rounds.
 *
 * A pattern match's confidence is the rule's `tags.confidence` label (high 0.9,
 * medium 0.7, anything else 0.5) plus up to 0.1 for the share of its conditions
 * that matched. computeVerdict denies a high-severity match at >= 0.8. In IEEE
 * doubles 0.7 + 0.1 is 0.7999999999999999, so a medium-label rule with every
 * condition matched landed one ulp under the deny threshold and got `ask` —
 * the documented answer, reached by rounding. The same quantity computed as an
 * integer percentage, or rounded to four places before comparing, is 0.8 and
 * denies.
 *
 * These tests pin the semantics instead of the rounding:
 *   - the label decides deny. Coverage never carries a label whose base is below
 *     the deny threshold up to it: `medium` peaks at 0.7999;
 *   - coverage may still lift a `low` label to exactly 0.6, the medium-severity
 *     ask threshold, which is what it has always done;
 *   - for every reachable coverage ratio, the verdict and auto-response
 *     decisions are the ones the previous scoring produced.
 */

import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ATREngine } from '../src/engine.js';
import { ruleConfidence } from '../src/rule-confidence.js';
import {
  computeVerdict,
  isAutoResponseEnabled,
  HIGH_SEVERITY_DENY_CONFIDENCE,
  MEDIUM_SEVERITY_ASK_CONFIDENCE,
} from '../src/verdict.js';
import type {
  AgentEvent,
  ATRConfidence,
  ATRMatch,
  ATRRule,
  ATRSeverity,
  VerdictOutcome,
} from '../src/types.js';

const MISSING = join(__dirname, '__missing_rules__');

const SEVERITIES: readonly ATRSeverity[] = ['critical', 'high', 'medium', 'low', 'informational'];
const LABELS: readonly ATRConfidence[] = ['high', 'medium', 'low'];

/** The scoring this module replaced, verbatim from src/engine.ts. */
function legacyConfidence(label: string | undefined, matchRatio: number): number {
  const baseConfidence = label === 'high' ? 0.9 : label === 'medium' ? 0.7 : 0.5;
  return Math.min(baseConfidence + matchRatio * 0.1, 1.0);
}

function verdictRule(
  severity: ATRSeverity,
  label: string | undefined,
  autoResponseThreshold?: string,
): ATRRule {
  return {
    id: 'ATR-2026-99990',
    title: 'Boundary fixture',
    status: 'stable',
    description: 'fixture',
    author: 'test',
    date: '2026/10/17',
    severity,
    tags: { category: 'prompt-injection', ...(label !== undefined ? { confidence: label } : {}) },
    agent_source: { type: 'llm_io' },
    detection: { conditions: [], condition: 'any' },
    response: { actions: ['alert'], auto_response_threshold: autoResponseThreshold },
  } as unknown as ATRRule;
}

function matchAt(rule: ATRRule, confidence: number): ATRMatch {
  return {
    rule,
    matchedConditions: ['0'],
    matchedPatterns: [],
    confidence,
    timestamp: '2026-10-17T00:00:00.000Z',
    scan_context: 'native',
  };
}

function outcomeAt(severity: ATRSeverity, confidence: number): VerdictOutcome {
  return computeVerdict([matchAt(verdictRule(severity, undefined), confidence)]).outcome;
}

describe('the rounding the previous scoring relied on', () => {
  it('0.7 + 0.1 is one ulp under the deny threshold', () => {
    expect(0.7 + 1 * 0.1).toBe(0.7999999999999999);
    expect(0.7 + 1 * 0.1 < HIGH_SEVERITY_DENY_CONFIDENCE).toBe(true);
  });

  it('the same quantity computed another way reaches it and would deny', () => {
    expect((70 + 10) / 100).toBe(0.8);
    expect(Math.round((0.7 + 0.1) * 10_000) / 10_000).toBe(0.8);
    expect(outcomeAt('high', (70 + 10) / 100)).toBe('deny');
  });

  it('0.5 + 0.1 lands exactly on the ask threshold (the mirror case)', () => {
    expect(0.5 + 1 * 0.1).toBe(MEDIUM_SEVERITY_ASK_CONFIDENCE);
  });
});

describe('verdict thresholds are inclusive', () => {
  it.each([
    ['high', HIGH_SEVERITY_DENY_CONFIDENCE, 'deny'],
    ['high', 0.7999, 'ask'],
    ['medium', MEDIUM_SEVERITY_ASK_CONFIDENCE, 'ask'],
    ['medium', 0.5999, 'allow'],
  ] as const)('%s severity at %s -> %s', (severity, confidence, outcome) => {
    expect(outcomeAt(severity, confidence)).toBe(outcome);
  });
});

describe('ruleConfidence', () => {
  it.each([
    // label, coverage ratio, confidence
    ['high', 0, 0.9],
    ['high', 0.5, 0.95],
    ['high', 1, 1],
    ['medium', 0, 0.7],
    ['medium', 0.5, 0.75],
    ['medium', 1, 0.7999],
    ['low', 0, 0.5],
    ['low', 0.5, 0.55],
    ['low', 1, 0.6],
    [undefined, 1, 0.6],
    ['medium-high', 1, 0.6],
  ] as const)('label %s at coverage %s -> %s', (label, ratio, expected) => {
    expect(ruleConfidence(label as ATRConfidence | undefined, ratio)).toBe(expected);
  });

  it.each([
    ['above 1', 1.5, 1],
    ['below 0', -1, 0],
    ['NaN', Number.NaN, 0],
  ] as const)('clamps a coverage ratio %s', (_name, ratio, clampedTo) => {
    for (const label of LABELS) {
      expect(ruleConfidence(label, ratio)).toBe(ruleConfidence(label, clampedTo));
    }
  });

  it('keeps a medium label strictly below the deny threshold at full coverage', () => {
    expect(ruleConfidence('medium', 1)).toBeLessThan(HIGH_SEVERITY_DENY_CONFIDENCE);
    // A full basis point of margin, not one ulp.
    expect(HIGH_SEVERITY_DENY_CONFIDENCE - ruleConfidence('medium', 1)).toBeGreaterThanOrEqual(0.0001 - 1e-12);
  });

  it('keeps the label bands disjoint and ordered', () => {
    expect(ruleConfidence('low', 1)).toBeLessThan(ruleConfidence('medium', 0));
    expect(ruleConfidence('medium', 1)).toBeLessThan(ruleConfidence('high', 0));
  });
});

describe('every reachable coverage ratio (k of n conditions, n <= 64)', () => {
  const ratios: number[] = [];
  for (let n = 1; n <= 64; n++) {
    for (let k = 0; k <= n; k++) ratios.push(k / n);
  }
  const labels: ReadonlyArray<ATRConfidence | undefined> = [...LABELS, undefined];

  it('is monotonic in coverage, so ranking within a label is unchanged', () => {
    const sorted = [...ratios].sort((a, b) => a - b);
    for (const label of labels) {
      for (let i = 1; i < sorted.length; i++) {
        expect(ruleConfidence(label, sorted[i]!)).toBeGreaterThanOrEqual(ruleConfidence(label, sorted[i - 1]!));
      }
    }
  });

  it('differs from the previous scoring only by float noise, except where it was one ulp under deny', () => {
    for (const label of labels) {
      for (const ratio of ratios) {
        const before = legacyConfidence(label, ratio);
        const after = ruleConfidence(label, ratio);
        if (label === 'medium' && ratio === 1) {
          expect(before).toBe(0.7999999999999999);
          expect(after).toBe(0.7999);
        } else {
          expect(Math.abs(after - before)).toBeLessThanOrEqual(1e-12);
        }
      }
    }
  });

  it('never changes a verdict or an auto-response decision', () => {
    for (const label of labels) {
      for (const ratio of ratios) {
        const before = legacyConfidence(label, ratio);
        const after = ruleConfidence(label, ratio);
        for (const severity of SEVERITIES) {
          expect(outcomeAt(severity, after)).toBe(outcomeAt(severity, before));
        }
        for (const threshold of ['high', 'medium', 'low']) {
          const rule = verdictRule('high', label, threshold);
          expect(isAutoResponseEnabled(matchAt(rule, after))).toBe(isAutoResponseEnabled(matchAt(rule, before)));
        }
      }
    }
  });
});

// --- Through the engine: severity x label x coverage, both condition formats ---

type Coverage = 'full' | 'partial';
type ConditionFormat = 'array' | 'named';

/**
 * Two conditions, alpha and bravo. "full" matches both under AND; "partial"
 * matches alpha only under OR, a coverage of 1/2.
 */
function engineRule(
  severity: ATRSeverity,
  label: ATRConfidence,
  coverage: Coverage,
  format: ConditionFormat,
): ATRRule {
  const detection = format === 'array'
    ? {
        condition: coverage === 'full' ? 'all' : 'any',
        conditions: [
          { field: 'content', operator: 'regex', value: 'alpha' },
          { field: 'content', operator: 'regex', value: 'bravo' },
        ],
      }
    : {
        condition: coverage === 'full' ? 'a AND b' : 'a OR b',
        conditions: {
          a: { field: 'content', patterns: ['alpha'] },
          b: { field: 'content', patterns: ['bravo'] },
        },
      };
  return {
    id: 'ATR-2026-99991',
    title: 'Boundary fixture',
    status: 'stable',
    maturity: 'stable',
    description: 'fixture',
    author: 'test',
    date: '2026/10/17',
    severity,
    tags: { category: 'prompt-injection', confidence: label },
    agent_source: { type: 'llm_io' },
    detection,
    response: { actions: ['alert'] },
  } as unknown as ATRRule;
}

function eventFor(coverage: Coverage): AgentEvent {
  return {
    type: 'llm_input',
    timestamp: '2026-10-17T00:00:00.000Z',
    content: coverage === 'full' ? 'alpha bravo' : 'alpha',
  };
}

/**
 * The verdict matrix as documented in docs/ARCHITECTURE.md §3.5, with the
 * label taking the place of the number: critical denies; high denies on a high
 * label only; medium asks on a medium or high label, and on a low label only
 * when every condition matched (exactly 0.6); low and informational allow.
 */
const MATRIX: ReadonlyArray<readonly [ATRSeverity, ATRConfidence, Coverage, VerdictOutcome]> = [
  ['critical', 'high', 'full', 'deny'],
  ['critical', 'high', 'partial', 'deny'],
  ['critical', 'medium', 'full', 'deny'],
  ['critical', 'medium', 'partial', 'deny'],
  ['critical', 'low', 'full', 'deny'],
  ['critical', 'low', 'partial', 'deny'],
  ['high', 'high', 'full', 'deny'],
  ['high', 'high', 'partial', 'deny'],
  ['high', 'medium', 'full', 'ask'],
  ['high', 'medium', 'partial', 'ask'],
  ['high', 'low', 'full', 'ask'],
  ['high', 'low', 'partial', 'ask'],
  ['medium', 'high', 'full', 'ask'],
  ['medium', 'high', 'partial', 'ask'],
  ['medium', 'medium', 'full', 'ask'],
  ['medium', 'medium', 'partial', 'ask'],
  ['medium', 'low', 'full', 'ask'],
  ['medium', 'low', 'partial', 'allow'],
  ['low', 'high', 'full', 'allow'],
  ['low', 'high', 'partial', 'allow'],
  ['low', 'medium', 'full', 'allow'],
  ['low', 'medium', 'partial', 'allow'],
  ['low', 'low', 'full', 'allow'],
  ['low', 'low', 'partial', 'allow'],
  ['informational', 'high', 'full', 'allow'],
  ['informational', 'high', 'partial', 'allow'],
  ['informational', 'medium', 'full', 'allow'],
  ['informational', 'medium', 'partial', 'allow'],
  ['informational', 'low', 'full', 'allow'],
  ['informational', 'low', 'partial', 'allow'],
];

/** Literal, not ruleConfidence(): the engine is checked against numbers, not against itself. */
const ENGINE_CONFIDENCE: Readonly<Record<ATRConfidence, Readonly<Record<Coverage, number>>>> = {
  high: { full: 1, partial: 0.95 },
  medium: { full: 0.7999, partial: 0.75 },
  low: { full: 0.6, partial: 0.55 },
};

describe.each(['array', 'named'] as const)('engine verdict, %s conditions', (format) => {
  it('covers every severity x label x coverage cell', () => {
    expect(MATRIX).toHaveLength(SEVERITIES.length * LABELS.length * 2);
  });

  it.each(MATRIX)('%s severity, %s label, %s coverage -> %s', async (severity, label, coverage, outcome) => {
    const engine = new ATREngine({ rules: [engineRule(severity, label, coverage, format)], rulesDir: MISSING });
    await engine.loadRules();

    const matches = engine.evaluate(eventFor(coverage));

    expect(matches).toHaveLength(1);
    expect(matches[0]!.confidence).toBe(ENGINE_CONFIDENCE[label][coverage]);
    expect(computeVerdict(matches).outcome).toBe(outcome);
  });
});

// --- Coverage is what the engine counts, not what the input contains ---

function fourConditionRule(severity: ATRSeverity, label: ATRConfidence, format: ConditionFormat): ATRRule {
  const words = ['alpha', 'bravo', 'charlie', 'delta'];
  const detection = format === 'array'
    ? {
        condition: 'any',
        conditions: words.map((w) => ({ field: 'content', operator: 'regex', value: w })),
      }
    : {
        condition: 'a OR b OR c OR d',
        conditions: Object.fromEntries(
          words.map((w, i) => ['abcd'[i]!, { field: 'content', patterns: [w] }]),
        ),
      };
  return { ...engineRule(severity, label, 'full', format), detection } as unknown as ATRRule;
}

/**
 * Every one of four OR'd conditions is present in the input. An array-format
 * `any` rule stops at the first hit, so its coverage is 1/4 however many would
 * have matched; named conditions are all evaluated, so theirs is 4/4. That is
 * existing behaviour and a reason the 0.7999 cell is reachable by so few
 * shipped rules: it needs `all`, or `any` with a single condition.
 */
describe('four OR-ed conditions, all present in the input', () => {
  it.each([
    // format, severity, label, confidence, outcome
    ['array', 'medium', 'low', 0.525, 'allow'],
    ['array', 'high', 'medium', 0.725, 'ask'],
    ['array', 'high', 'high', 0.925, 'deny'],
    ['named', 'medium', 'low', 0.6, 'ask'],
    ['named', 'high', 'medium', 0.7999, 'ask'],
    ['named', 'high', 'high', 1, 'deny'],
  ] as const)('%s format, %s severity, %s label -> %s, %s', async (format, severity, label, confidence, outcome) => {
    const engine = new ATREngine({ rules: [fourConditionRule(severity, label, format)], rulesDir: MISSING });
    await engine.loadRules();

    const matches = engine.evaluate({
      type: 'llm_input',
      timestamp: '2026-10-17T00:00:00.000Z',
      content: 'alpha bravo charlie delta',
    });

    expect(matches).toHaveLength(1);
    expect(matches[0]!.confidence).toBe(confidence);
    expect(computeVerdict(matches).outcome).toBe(outcome);
  });
});

// --- Trace rules: the label alone, no coverage bonus ---

function traceRule(severity: ATRSeverity, label: ATRConfidence): ATRRule {
  return {
    id: 'ATR-2026-99992',
    title: 'Trace boundary fixture',
    status: 'stable',
    maturity: 'stable',
    description: 'fixture',
    author: 'test',
    date: '2026/10/17',
    severity,
    tags: { category: 'agent-manipulation', confidence: label },
    agent_source: { type: 'agent_trace' },
    detection: {
      conditions: [],
      condition: 'any',
      method: 'trace',
      trace: {
        forbid: [
          {
            shape: { 'span.kind': 'TOOL', attributes: { 'tool.privilege': 'exfil' } },
            preceded_by: { 'span.kind': 'RETRIEVER', attributes: { 'source.trust': 'untrusted' } },
          },
        ],
      },
    },
    response: { actions: ['alert'] },
  } as unknown as ATRRule;
}

describe('engine verdict, trace rules', () => {
  it.each([
    // severity, label, confidence, outcome
    ['high', 'high', 0.9, 'deny'],
    ['high', 'medium', 0.7, 'ask'],
    ['high', 'low', 0.5, 'ask'],
    ['medium', 'medium', 0.7, 'ask'],
    ['medium', 'low', 0.5, 'allow'],
  ] as const)('%s severity, %s label -> %s, %s', async (severity, label, confidence, outcome) => {
    const engine = new ATREngine({ rules: [traceRule(severity, label)], rulesDir: MISSING });
    await engine.loadRules();

    const matches = engine.evaluate({
      type: 'llm_input',
      timestamp: '2026-10-17T00:00:00.000Z',
      content: '',
      trace: {
        spans: [
          { id: 'r1', 'span.kind': 'RETRIEVER', attributes: { 'source.trust': 'untrusted' } },
          { id: 't1', 'span.kind': 'TOOL', attributes: { 'tool.privilege': 'exfil' } },
        ],
      },
    });

    expect(matches).toHaveLength(1);
    expect(matches[0]!.confidence).toBe(confidence);
    expect(computeVerdict(matches).outcome).toBe(outcome);
  });
});
