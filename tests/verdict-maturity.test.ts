/**
 * Maturity ceiling on the verdict.
 *
 * Pins the contract that a rule's blocking authority comes from its maturity,
 * not only from its severity:
 *
 *   stable       -> may deny
 *   test         -> may at most ask
 *   experimental -> may at most allow (still reported, never blocking)
 *   draft / deprecated / missing / unrecognised -> may at most allow
 *
 * and that the ceiling is applied PER RULE before the matches are folded, so an
 * unproven loud rule cannot suppress a proven quiet one.
 *
 * Covers the pure function (src/verdict.ts), the engine path
 * (engine.evaluateWithVerdict, which is what the hook actually calls) and the
 * hook contract itself (permissionDecision), because the defect this closes was
 * only reachable through the full path: the lane gate defaults to `hunt`, which
 * admits every maturity.
 */

import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import {
  computeVerdict,
  maturityCeiling,
  outcomeForMatch,
  OUTCOME_STRICTNESS,
} from '../src/verdict.js';
import { ATREngine } from '../src/engine.js';
import { HookHandler } from '../src/hook-handler.js';
import { ActionExecutor } from '../src/action-executor.js';
import { DefaultAdapter } from '../src/adapters/default-adapter.js';
import type { ATRMatch, ATRRule, ATRSeverity, AgentEvent, HookInput } from '../src/types.js';

/** A rules directory that does not exist, so only the injected rules load. */
const MISSING_RULES_DIR = join(__dirname, '__missing_rules__');

function makeRule(overrides: {
  id?: string;
  severity?: ATRSeverity;
  maturity?: string;
  title?: string;
  actions?: string[];
}): ATRRule {
  const rule: Record<string, unknown> = {
    id: overrides.id ?? 'TEST-001',
    // Title defaults to the id: buildReason prints the title, so this is what
    // lets a reason assertion identify WHICH rule decided the verdict.
    title: overrides.title ?? overrides.id ?? 'TEST-001',
    status: 'stable',
    description: 'A test rule',
    author: 'test',
    date: '2026-01-01',
    severity: overrides.severity ?? 'critical',
    tags: { category: 'prompt-injection' },
    agent_source: { type: 'llm_io' },
    detection: { conditions: [], condition: 'any' },
    response: { actions: overrides.actions ?? ['alert'] },
  };
  // Only set the key when asked, so `maturity: undefined` and "key absent" are
  // the same thing here — the case a real rule file with no maturity produces.
  if (overrides.maturity !== undefined) rule['maturity'] = overrides.maturity;
  return rule as unknown as ATRRule;
}

function makeMatch(rule: ATRRule, confidence: number): ATRMatch {
  return {
    rule,
    matchedConditions: ['0'],
    matchedPatterns: ['test_pattern'],
    confidence,
    timestamp: new Date().toISOString(),
    scan_context: 'native',
  };
}

/**
 * A rule that fires on the literal string `attackpattern`.
 *
 * `sourceType` must line up with the event type the engine is handed:
 * `llm_io` for `llm_input` events, `tool_call` for the PreToolUse hook path
 * (engine.ts skips a rule whose agent_source.type differs from the event's).
 */
function firingRule(
  id: string,
  severity: ATRSeverity,
  maturity?: string,
  sourceType: 'llm_io' | 'tool_call' = 'llm_io',
): ATRRule {
  const rule = makeRule({ id, severity, maturity, title: id });
  return {
    ...rule,
    agent_source: { type: sourceType },
    detection: {
      conditions: [{ field: 'content', operator: 'regex', value: 'attackpattern' }],
      condition: 'any',
    },
  } as unknown as ATRRule;
}

async function engineWith(
  rules: ATRRule[],
  config: Record<string, unknown> = {},
): Promise<ATREngine> {
  const engine = new ATREngine({ rules, rulesDir: MISSING_RULES_DIR, ...config });
  await engine.loadRules();
  return engine;
}

const event = (content: string): AgentEvent => ({
  type: 'llm_input',
  timestamp: new Date().toISOString(),
  content,
});

// ---------------------------------------------------------------------------
// maturityCeiling
// ---------------------------------------------------------------------------

describe('maturityCeiling', () => {
  it('gives stable the full matrix, test at most ask, experimental at most allow', () => {
    expect(maturityCeiling('stable')).toBe('deny');
    expect(maturityCeiling('test')).toBe('ask');
    expect(maturityCeiling('experimental')).toBe('allow');
  });

  it('treats draft and deprecated as non-blocking', () => {
    expect(maturityCeiling('draft')).toBe('allow');
    expect(maturityCeiling('deprecated')).toBe('allow');
  });

  it('treats an undeterminable maturity as the most restrictive, never as stable', () => {
    for (const bad of [undefined, null, '', '   ', 'STABLE', 'Stable', 'needs-human-poc', 42, {}, []]) {
      expect(maturityCeiling(bad)).toBe('allow');
    }
  });

  it('tolerates surrounding whitespace on an otherwise valid value', () => {
    // normalizeMaturity trims; pinned so the "unrecognised -> allow" case above
    // is understood as unrecognised, not as "any string that is not exact".
    expect(maturityCeiling(' stable ')).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// computeVerdict — the four required pins
// ---------------------------------------------------------------------------

describe('computeVerdict maturity ceiling', () => {
  it('does NOT deny for an experimental critical rule on its own', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'critical', maturity: 'experimental' }), 0.99),
    ]);

    expect(verdict.outcome).not.toBe('deny');
    expect(verdict.outcome).toBe('allow');
    // Still reported: the ceiling withholds blocking authority, not visibility.
    expect(verdict.matchCount).toBe(1);
    expect(verdict.highestSeverity).toBe('critical');
  });

  it('still denies for a stable critical rule', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'critical', maturity: 'stable' }), 0.95),
    ]);

    expect(verdict.outcome).toBe('deny');
  });

  it('denies when an experimental critical and a stable critical both match', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ id: 'EXP', severity: 'critical', maturity: 'experimental' }), 0.99),
      makeMatch(makeRule({ id: 'STA', severity: 'critical', maturity: 'stable' }), 0.9),
    ]);

    expect(verdict.outcome).toBe('deny');
    // The reason must name the rule that actually earned the block.
    expect(verdict.reason).toContain('STA');
  });

  it('does NOT deny when the maturity field is missing entirely', () => {
    const rule = makeRule({ severity: 'critical' });
    expect('maturity' in (rule as unknown as Record<string, unknown>)).toBe(false);

    const verdict = computeVerdict([makeMatch(rule, 0.99)]);

    expect(verdict.outcome).not.toBe('deny');
    expect(verdict.outcome).toBe('allow');
  });

  // -------------------------------------------------------------------------
  // per-rule ceiling, then fold  (the design question)
  // -------------------------------------------------------------------------

  it('an experimental critical does not suppress a stable medium: verdict is ask', () => {
    // Sorted the way the engine sorts: critical first. Capping the highest
    // severity match alone would return `allow` and lose the stable rule's ask.
    const verdict = computeVerdict([
      makeMatch(makeRule({ id: 'EXP-CRIT', severity: 'critical', maturity: 'experimental' }), 0.99),
      makeMatch(makeRule({ id: 'STA-MED', severity: 'medium', maturity: 'stable' }), 0.65),
    ]);

    expect(verdict.outcome).toBe('ask');
    expect(verdict.reason).toContain('STA-MED');
    // highestSeverity still describes the corpus of matches, not the decision.
    expect(verdict.highestSeverity).toBe('critical');
  });

  it('a test-maturity critical rule asks rather than denies', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'critical', maturity: 'test' }), 0.99),
    ]);

    expect(verdict.outcome).toBe('ask');
  });

  it('a test-maturity high rule at high confidence asks rather than denies', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'high', maturity: 'test' }), 0.95),
    ]);

    expect(verdict.outcome).toBe('ask');
  });

  it('the ceiling never RAISES an outcome', () => {
    // stable + low severity must stay allow: the ceiling is an upper bound only.
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'low', maturity: 'stable' }), 0.99),
    ]);

    expect(verdict.outcome).toBe('allow');
  });

  it('takes the strictest surviving outcome across many matches', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ id: 'RULE-A', severity: 'critical', maturity: 'draft' }), 0.99),
      makeMatch(makeRule({ id: 'RULE-B', severity: 'critical', maturity: 'experimental' }), 0.98),
      makeMatch(makeRule({ id: 'RULE-C', severity: 'high', maturity: 'test' }), 0.9),
      makeMatch(makeRule({ id: 'RULE-D', severity: 'medium', maturity: 'stable' }), 0.2),
    ]);

    expect(verdict.outcome).toBe('ask'); // from RULE-C, the only one able to ask
    expect(verdict.reason).toContain('RULE-C');
  });

  it('records in the reason when the ceiling lowered the verdict', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'critical', maturity: 'experimental' }), 0.99),
    ]);

    expect(verdict.reason).toContain('maturity-capped from DENY');
  });

  it('adds no cap note when nothing was capped', () => {
    const verdict = computeVerdict([
      makeMatch(makeRule({ severity: 'critical', maturity: 'stable' }), 0.99),
    ]);

    expect(verdict.reason).not.toContain('maturity-capped');
  });
});

// ---------------------------------------------------------------------------
// outcomeForMatch / OUTCOME_STRICTNESS
// ---------------------------------------------------------------------------

describe('outcomeForMatch', () => {
  it('computes each rule ceiling independently of the other matches', () => {
    const exp = makeMatch(makeRule({ severity: 'critical', maturity: 'experimental' }), 0.99);
    const sta = makeMatch(makeRule({ severity: 'medium', maturity: 'stable' }), 0.65);

    expect(outcomeForMatch(exp)).toBe('allow');
    expect(outcomeForMatch(sta)).toBe('ask');
  });

  it('orders outcomes allow < ask < deny', () => {
    expect(OUTCOME_STRICTNESS.allow).toBeLessThan(OUTCOME_STRICTNESS.ask);
    expect(OUTCOME_STRICTNESS.ask).toBeLessThan(OUTCOME_STRICTNESS.deny);
  });
});

// ---------------------------------------------------------------------------
// opt-out
// ---------------------------------------------------------------------------

describe('denyIgnoresMaturity opt-out', () => {
  it('is off by default — the safe side', () => {
    const matches = [makeMatch(makeRule({ severity: 'critical', maturity: 'experimental' }), 0.99)];

    expect(computeVerdict(matches).outcome).toBe('allow');
    expect(computeVerdict(matches, {}).outcome).toBe('allow');
    expect(computeVerdict(matches, { denyIgnoresMaturity: false }).outcome).toBe('allow');
  });

  it('restores the old severity-only behaviour when explicitly enabled', () => {
    const opts = { denyIgnoresMaturity: true };

    expect(
      computeVerdict([makeMatch(makeRule({ severity: 'critical', maturity: 'experimental' }), 0.99)], opts).outcome,
    ).toBe('deny');
    expect(
      computeVerdict([makeMatch(makeRule({ severity: 'critical' }), 0.99)], opts).outcome,
    ).toBe('deny');
    expect(
      computeVerdict([makeMatch(makeRule({ severity: 'high', maturity: 'draft' }), 0.85)], opts).outcome,
    ).toBe('deny');
  });

  it('with the opt-out on, the fold reproduces "highest severity match decides"', () => {
    const opts = { denyIgnoresMaturity: true };
    const verdict = computeVerdict(
      [
        makeMatch(makeRule({ id: 'HIGH-LOWCONF', severity: 'high', maturity: 'experimental' }), 0.7),
        makeMatch(makeRule({ id: 'MED', severity: 'medium', maturity: 'stable' }), 0.99),
      ],
      opts,
    );

    expect(verdict.outcome).toBe('ask');
    expect(verdict.reason).toContain('HIGH-LOWCONF');
    expect(verdict.reason).not.toContain('maturity-capped');
  });
});

// ---------------------------------------------------------------------------
// the shipped path: engine (default lane = hunt) and the hook contract
// ---------------------------------------------------------------------------

describe('engine.evaluateWithVerdict honours the ceiling in the default lane', () => {
  it('an experimental critical rule fires but does not block', async () => {
    const engine = await engineWith([firingRule('ATR-TEST-EXP', 'critical', 'experimental')]);

    const { verdict } = await engine.evaluateWithVerdict(event('attackpattern here'));

    expect(verdict.matchCount).toBe(1); // it fired — hunt lane admits it
    expect(verdict.outcome).not.toBe('deny');
  });

  it('a stable critical rule still blocks', async () => {
    const engine = await engineWith([firingRule('ATR-TEST-STA', 'critical', 'stable')]);

    const { verdict } = await engine.evaluateWithVerdict(event('attackpattern here'));

    expect(verdict.outcome).toBe('deny');
  });

  it('a rule file with no maturity at all does not block', async () => {
    const engine = await engineWith([firingRule('ATR-TEST-NONE', 'critical')]);

    const { verdict } = await engine.evaluateWithVerdict(event('attackpattern here'));

    expect(verdict.matchCount).toBe(1);
    expect(verdict.outcome).not.toBe('deny');
  });

  it('denyIgnoresMaturity: true on the engine config restores blocking', async () => {
    const engine = await engineWith([firingRule('ATR-TEST-EXP', 'critical', 'experimental')], {
      denyIgnoresMaturity: true,
    });

    const { verdict } = await engine.evaluateWithVerdict(event('attackpattern here'));

    expect(verdict.outcome).toBe('deny');
  });
});

describe('hook decision (PreToolUse -> permissionDecision)', () => {
  const hookInput: HookInput = {
    hook: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { content: 'attackpattern' },
  } as HookInput;

  async function handlerWith(rule: ATRRule): Promise<HookHandler> {
    const engine = await engineWith([rule]);
    return new HookHandler({
      engine,
      executor: new ActionExecutor({ adapter: new DefaultAdapter(), dryRun: true }),
      failOpen: true,
    });
  }

  it('does not deny on an experimental critical rule', async () => {
    const handler = await handlerWith(
      firingRule('ATR-TEST-EXP', 'critical', 'experimental', 'tool_call'),
    );

    const output = await handler.handlePreToolUse(hookInput);

    expect(output.matched_rules).toContain('ATR-TEST-EXP'); // it fired
    expect(output.decision).not.toBe('deny');
  });

  it('denies on a stable critical rule', async () => {
    const handler = await handlerWith(
      firingRule('ATR-TEST-STA', 'critical', 'stable', 'tool_call'),
    );

    const output = await handler.handlePreToolUse(hookInput);

    expect(output.decision).toBe('deny');
  });
});
