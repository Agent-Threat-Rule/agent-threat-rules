/**
 * Enforcement policy: blocking is opt-in, and the lane finally has an entrance.
 *
 * WHAT THIS PINS
 *
 * 1. Blocking off (the default) must OMIT permissionDecision, never downgrade it
 *    to "allow". In the Claude Code PreToolUse contract "allow" is affirmative
 *    approval — it suppresses the host's own permission prompt — so a guard that
 *    answered "allow" where it used to answer "ask" would make the host LESS
 *    safe than having no hook at all.
 *
 * 2. Blocking off must also stop the second channel. Before this, a benign
 *    `Bash{command:"ls -la"}` produced permissionDecision "allow" while the
 *    ActionExecutor really invoked blockTool on the adapter: the hook said yes
 *    and the action channel said no, on the same event. Observation actions
 *    (alert / snapshot / shadow / escalate) must keep running — suppressing them
 *    would cost detection.
 *
 * 3. Blocking on must reproduce the historical severity+confidence matrix
 *    exactly, so turning the switch on is not a second behaviour to review.
 *
 * 4. Detection is never affected by either switch. Same matches, same count,
 *    same severity, in both modes.
 *
 * The destructive/observational split is NOT redefined here: these tests read
 * the same blast-radius ladder the eligibility gate uses
 * (src/quality/action-eligibility.ts), so a new adapter method cannot land on
 * the wrong side of the switch without that module classifying it first.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  resolveLaneOrWarn,
  resolveBlockingOrWarn,
  resetEnforcementWarnings,
  DEFAULT_BLOCKING,
  DEFAULT_LANE,
  isEnforcementAction,
  parseBooleanFlag,
  parseLane,
  resolveBlocking,
  resolveLane,
} from '../src/enforcement.js';
import { ATREngine } from '../src/engine.js';
import { ActionExecutor } from '../src/action-executor.js';
import {
  HookHandler,
  toClaudeCodePreToolUse,
  toClaudeCodePostToolUse,
} from '../src/hook-handler.js';
import { TIERED_ACTIONS, actionTier, ACTION_TIERS } from '../src/quality/action-eligibility.js';
import type {
  ActionResult,
  AgentEvent,
  ATRRule,
  ExecutionContext,
  HookInput,
  HookOutput,
  PlatformAdapter,
} from '../src/types.js';

const CLI = new URL('../src/cli.ts', import.meta.url).pathname;

// --- helpers ---------------------------------------------------------------

/** Records which PlatformAdapter methods were actually invoked, by name. */
class RecordingAdapter implements PlatformAdapter {
  readonly name = 'recording';
  calls: string[] = [];

  private record(method: string, action: string): ActionResult {
    this.calls.push(method);
    return Object.freeze({
      action: action as ActionResult['action'],
      success: true,
      message: `recorded ${method}`,
      timestamp: new Date().toISOString(),
    });
  }
  async blockInput() { return this.record('blockInput', 'block_input'); }
  async blockOutput() { return this.record('blockOutput', 'block_output'); }
  async blockTool() { return this.record('blockTool', 'block_tool'); }
  async quarantineSession() { return this.record('quarantineSession', 'quarantine_session'); }
  async resetContext() { return this.record('resetContext', 'reset_context'); }
  async alert() { return this.record('alert', 'alert'); }
  async shadow() { return this.record('shadow', 'shadow'); }
  async snapshot() { return this.record('snapshot', 'snapshot'); }
  async escalate() { return this.record('escalate', 'escalate'); }
  async reducePermissions() { return this.record('reducePermissions', 'reduce_permissions'); }
  async killAgent() { return this.record('killAgent', 'kill_agent'); }
}

const MARKER = 'enforcement_fixture_marker';

/** A critical rule that declares one destructive and two observational actions. */
function fixtureRule(overrides: Partial<ATRRule> = {}): ATRRule {
  return {
    title: 'Enforcement fixture',
    id: 'ATR-2026-09101',
    status: 'experimental',
    description: 'Fixture rule for enforcement tests.',
    author: 'ATR Community',
    date: '2026/08/14',
    schema_version: '0.1',
    maturity: 'test',
    severity: 'critical',
    tags: {
      category: 'excessive-autonomy',
      subcategory: 'fixture',
      scan_target: 'both',
      confidence: 'high',
    },
    agent_source: { type: 'tool_call', framework: ['any'], provider: ['any'] },
    detection: {
      method: 'pattern',
      condition: 'any',
      conditions: [
        { field: 'content', operator: 'regex', value: MARKER, description: 'fixture' },
      ],
    },
    response: {
      actions: ['block_tool', 'alert', 'snapshot'],
      message_template: 'fixture',
    },
    ...overrides,
  } as unknown as ATRRule;
}

function markerEvent(): AgentEvent {
  return Object.freeze({
    type: 'tool_call',
    timestamp: new Date().toISOString(),
    content: MARKER,
    fields: Object.freeze({ tool_name: 'Read', tool_args: '{}', content: MARKER }),
  }) as AgentEvent;
}

async function loadedEngine(config: Record<string, unknown> = {}): Promise<ATREngine> {
  const engine = new ATREngine({ rules: [fixtureRule()], ...config });
  const count = await engine.loadRules();
  // CONTROL: the constructor does not compile patterns. Without loadRules() the
  // engine matches nothing and every assertion below would pass vacuously.
  expect(count).toBeGreaterThan(0);
  return engine;
}

const hookOutput = (o: Partial<HookOutput>): HookOutput =>
  Object.freeze({ decision: 'allow', reason: 'r', ...o }) as HookOutput;

/** Restore process.env between tests — these tests set ATR_* deliberately. */
let savedEnv: NodeJS.ProcessEnv;
beforeEach(() => {
  savedEnv = { ...process.env };
  delete process.env['ATR_LANE'];
  delete process.env['ATR_BLOCKING'];
});
afterEach(() => {
  process.env = savedEnv;
});

// --- 1. policy resolution --------------------------------------------------

describe('enforcement policy resolution', () => {
  it('defaults to advisory hunt when nothing is configured', () => {
    expect(DEFAULT_LANE).toBe('hunt');
    expect(DEFAULT_BLOCKING).toBe(false);
    expect(resolveLane(undefined, {})).toBe('hunt');
    expect(resolveBlocking(undefined, {})).toBe(false);
  });

  it('reads the lane from the environment', () => {
    expect(resolveLane(undefined, { ATR_LANE: 'enforce' })).toBe('enforce');
    expect(resolveLane(undefined, { ATR_LANE: 'alert' })).toBe('alert');
    expect(resolveLane(undefined, { ATR_LANE: '  hunt ' })).toBe('hunt');
  });

  it('lets explicit config beat the environment, in both directions', () => {
    expect(resolveLane('enforce', { ATR_LANE: 'hunt' })).toBe('enforce');
    expect(resolveLane('hunt', { ATR_LANE: 'enforce' })).toBe('hunt');
    expect(resolveBlocking(true, { ATR_BLOCKING: '0' })).toBe(true);
    expect(resolveBlocking(false, { ATR_BLOCKING: '1' })).toBe(false);
  });

  it('treats an empty environment value as unset', () => {
    expect(resolveLane(undefined, { ATR_LANE: '' })).toBe('hunt');
    expect(resolveBlocking(undefined, { ATR_BLOCKING: '   ' })).toBe(false);
  });

  it('accepts the documented truthy/falsy spellings for blocking', () => {
    for (const v of ['1', 'true', 'TRUE', 'yes', 'on']) {
      expect(resolveBlocking(undefined, { ATR_BLOCKING: v })).toBe(true);
    }
    for (const v of ['0', 'false', 'no', 'off']) {
      expect(resolveBlocking(undefined, { ATR_BLOCKING: v })).toBe(false);
    }
  });

  it('throws on an unrecognised value instead of silently falling back', () => {
    // A silent fallback is the worst failure mode here: the operator believes
    // they configured enforcement and they did not.
    expect(() => resolveLane('enfroce')).toThrow(/Invalid lane/);
    expect(() => resolveLane(undefined, { ATR_LANE: 'block' })).toThrow(/ATR_LANE/);
    expect(() => resolveBlocking(undefined, { ATR_BLOCKING: 'enabled' })).toThrow(/ATR_BLOCKING/);
    expect(parseLane('nope')).toBeNull();
    expect(parseBooleanFlag('maybe')).toBeNull();
  });

  it('derives the enforce/observe split from the blast-radius ladder', () => {
    for (const action of TIERED_ACTIONS) {
      expect(isEnforcementAction(action)).toBe(actionTier(action) > ACTION_TIERS.OBSERVE);
    }
    expect(isEnforcementAction('alert')).toBe(false);
    expect(isEnforcementAction('snapshot')).toBe(false);
    expect(isEnforcementAction('escalate')).toBe(false);
    expect(isEnforcementAction('shadow')).toBe(false);
    expect(isEnforcementAction('block_tool')).toBe(true);
    expect(isEnforcementAction('kill_agent')).toBe(true);
    expect(isEnforcementAction('quarantine_session')).toBe(true);
    expect(isEnforcementAction('reduce_permissions')).toBe(true);
  });
});

// --- 2. lane entry points --------------------------------------------------

describe('lane has a real entrance', () => {
  it('is hunt by default', async () => {
    const engine = await loadedEngine();
    expect(engine.getLane()).toBe('hunt');
  });

  it('takes the lane from programmatic config', async () => {
    const engine = await loadedEngine({ lane: 'enforce' });
    expect(engine.getLane()).toBe('enforce');
  });

  it('takes the lane from ATR_LANE when config is silent', async () => {
    process.env['ATR_LANE'] = 'alert';
    const engine = await loadedEngine();
    expect(engine.getLane()).toBe('alert');
  });

  it('prefers explicit config over ATR_LANE', async () => {
    process.env['ATR_LANE'] = 'hunt';
    const engine = await loadedEngine({ lane: 'enforce' });
    expect(engine.getLane()).toBe('enforce');
  });

  // This expectation was the reverse until review measured what it costs.
  // Throwing here meant `ATR_BLOCKING=enabled npx atr guard` exited 1 with an
  // empty stdout and no guard at all, and a typo'd ATR_LANE in a shell profile
  // crashed the VS Code extension from this constructor. Neither of those
  // processes asked to read the environment; the environment is ambient.
  //
  // So the constructor warns and falls back, and the throwing resolver stays
  // for an explicit argument, which is the caller's own bug. The warning is the
  // part that matters -- a silent fallback here would be the failure the
  // throwing version existed to prevent.
  it('an invalid ATR_LANE warns and falls back rather than crashing the caller', () => {
    process.env['ATR_LANE'] = 'enfroce';
    const seen: string[] = [];
    const write = process.stderr.write;
    (process.stderr as { write: unknown }).write = (chunk: string) => {
      seen.push(String(chunk));
      return true;
    };
    try {
      const engine = new ATREngine({ rules: [fixtureRule()] });
      expect(engine.getLane()).toBe('hunt');
    } finally {
      (process.stderr as { write: unknown }).write = write;
    }
    expect(seen.join('')).toMatch(/ATR_LANE/);
  });

  it('an explicit invalid lane still throws', () => {
    expect(() => new ATREngine({ rules: [fixtureRule()], lane: 'enfroce' as never })).toThrow(
      /lane/i,
    );
  });

  it('actually gates firing: a maturity=test rule fires in hunt, not in enforce', async () => {
    const hunt = await loadedEngine();
    expect(hunt.evaluate(markerEvent()).length).toBeGreaterThan(0);

    process.env['ATR_LANE'] = 'enforce';
    const enforce = await loadedEngine();
    expect(enforce.getLane()).toBe('enforce');
    expect(enforce.evaluate(markerEvent())).toHaveLength(0);
  });
});

// --- 3. channel A: the Claude Code contract --------------------------------

describe('hook contract omits the decision when blocking is off', () => {
  it('emits NO permissionDecision by default, for every outcome', () => {
    for (const decision of ['allow', 'ask', 'deny'] as const) {
      const p = toClaudeCodePreToolUse(hookOutput({ decision, reason: `r-${decision}` }));
      // The whole hookSpecificOutput envelope is dropped: a partial one is not
      // a shape this contract is known to accept, extra top-level atr_* keys
      // demonstrably are.
      expect(p['hookSpecificOutput']).toBeUndefined();
      expect(p['atr_hook_event']).toBe('PreToolUse');
      expect(JSON.stringify(p)).not.toContain('permissionDecision');
    }
  });

  it('never downgrades a block to "allow" — the field is absent, not neutral', () => {
    const p = toClaudeCodePreToolUse(hookOutput({ decision: 'deny', reason: 'rm -rf /' }));
    const serialized = JSON.stringify(p);
    expect(serialized).not.toContain('permissionDecision');
    // An `ask` must not become an `allow` either: that is the exact regression
    // that made `rm -rf /` stop prompting the user in an earlier attempt.
    const asked = toClaudeCodePreToolUse(hookOutput({ decision: 'ask' }));
    expect(JSON.stringify(asked)).not.toContain('"allow"');
  });

  it('still reports the detection while advisory', () => {
    const p = toClaudeCodePreToolUse(
      hookOutput({
        decision: 'deny',
        reason: 'DENY: something [critical/93% confidence] (2 rules matched)',
        matched_rules: Object.freeze(['ATR-2026-00062', 'ATR-2026-00040']),
      })
    );
    expect(p['atr_advisory']).toBe(true);
    expect(p['atr_decision']).toBe('deny');
    expect(p['atr_reason']).toContain('critical/93%');
    expect(p['matched_rules']).toEqual(['ATR-2026-00062', 'ATR-2026-00040']);
  });

  it('emits the 1:1 permissionDecision once blocking is on', () => {
    for (const decision of ['allow', 'ask', 'deny'] as const) {
      const p = toClaudeCodePreToolUse(
        hookOutput({ decision, reason: `r-${decision}` }),
        { blocking: true }
      );
      const hso = p['hookSpecificOutput'] as Record<string, unknown>;
      expect(hso['permissionDecision']).toBe(decision);
      expect(hso['permissionDecisionReason']).toBe(`r-${decision}`);
      expect(p['atr_advisory']).toBeUndefined();
    }
  });

  it('PostToolUse: no block sentinel while advisory, block once enabled', () => {
    for (const decision of ['deny', 'ask'] as const) {
      const advisory = toClaudeCodePostToolUse(hookOutput({ decision }));
      expect(advisory['decision']).toBeUndefined();
      expect(advisory['atr_advisory']).toBe(true);
      expect(advisory['atr_decision']).toBe(decision);

      const blocking = toClaudeCodePostToolUse(hookOutput({ decision }), { blocking: true });
      expect(blocking['decision']).toBe('block');
    }
    expect(
      toClaudeCodePostToolUse(hookOutput({ decision: 'allow' }), { blocking: true })['decision']
    ).toBeUndefined();
  });
});

// --- 4. channel B: response actions ----------------------------------------

describe('response actions obey the same switch', () => {
  it('suppresses enforcement actions and keeps observation ones (real engine path)', async () => {
    const engine = await loadedEngine();
    const adapter = new RecordingAdapter();
    const executor = new ActionExecutor({ adapter });
    expect(executor.isBlocking()).toBe(false);

    const { verdict } = await engine.evaluateWithVerdict(markerEvent(), executor);

    // Detection is untouched: the rule matched and still DECLARES block_tool.
    expect(verdict.matchCount).toBeGreaterThan(0);
    expect(verdict.actions).toContain('block_tool');

    // But the adapter was never asked to block. CONTROL: alert/snapshot prove
    // the executor really reached the adapter, so "no blockTool" means
    // suppressed, not "never got there".
    expect(adapter.calls).toContain('alert');
    expect(adapter.calls).toContain('snapshot');
    expect(adapter.calls).not.toContain('blockTool');
  });

  it('dispatches them once blocking is on', async () => {
    const engine = await loadedEngine();
    const adapter = new RecordingAdapter();
    const executor = new ActionExecutor({ adapter, blocking: true });
    expect(executor.isBlocking()).toBe(true);

    await engine.evaluateWithVerdict(markerEvent(), executor);

    expect(adapter.calls).toContain('blockTool');
    expect(adapter.calls).toContain('alert');
    expect(adapter.calls).toContain('snapshot');
  });

  it('honours ATR_BLOCKING when no explicit flag is passed', async () => {
    process.env['ATR_BLOCKING'] = '1';
    const engine = await loadedEngine();
    const adapter = new RecordingAdapter();
    await engine.evaluateWithVerdict(markerEvent(), new ActionExecutor({ adapter }));
    expect(adapter.calls).toContain('blockTool');
  });

  it('lets an explicit false beat ATR_BLOCKING', async () => {
    process.env['ATR_BLOCKING'] = '1';
    const engine = await loadedEngine();
    const adapter = new RecordingAdapter();
    await engine.evaluateWithVerdict(
      markerEvent(),
      new ActionExecutor({ adapter, blocking: false })
    );
    expect(adapter.calls).not.toContain('blockTool');
    expect(adapter.calls).toContain('alert');
  });

  it('reports every suppressed action instead of dropping it silently', async () => {
    const adapter = new RecordingAdapter();
    const executor = new ActionExecutor({ adapter });
    const context = {
      event: markerEvent(),
      matches: [],
      verdict: {
        outcome: 'deny',
        reason: 'x',
        matchCount: 1,
        highestSeverity: 'critical',
        highestConfidence: 0.9,
        actions: Object.freeze(['kill_agent', 'block_input', 'alert'] as const),
        matches: Object.freeze([]),
        timestamp: new Date().toISOString(),
      },
    } as unknown as ExecutionContext;

    const results = await executor.execute(context);
    const byAction = new Map(results.map((r) => [r.action, r]));

    expect(byAction.get('kill_agent')!.message).toMatch(/Suppressed kill_agent \(tier terminate\)/);
    expect(byAction.get('block_input')!.message).toMatch(/Suppressed block_input \(tier interrupt\)/);
    expect(byAction.get('alert')!.message).toBe('recorded alert');
    expect(adapter.calls).toEqual(['alert']);
  });

  it('suppression wins over dry-run: "would execute" is false for a forbidden action', async () => {
    const adapter = new RecordingAdapter();
    const executor = new ActionExecutor({ adapter, dryRun: true });
    const context = {
      event: markerEvent(),
      matches: [],
      verdict: {
        outcome: 'deny',
        reason: 'x',
        matchCount: 1,
        highestSeverity: 'critical',
        highestConfidence: 0.9,
        actions: Object.freeze(['block_tool', 'alert'] as const),
        matches: Object.freeze([]),
        timestamp: new Date().toISOString(),
      },
    } as unknown as ExecutionContext;

    const results = await executor.execute(context);
    const blockTool = results.find((r) => r.action === 'block_tool')!;
    expect(blockTool.message).toContain('[advisory]');
    expect(blockTool.message).not.toContain('[dry-run]');
  });
});

// --- 5. handler wiring -----------------------------------------------------

describe('HookHandler carries the policy', () => {
  it('is advisory by default and keeps the verdict intact', async () => {
    const engine = await loadedEngine();
    const adapter = new RecordingAdapter();
    const handler = new HookHandler({
      engine,
      executor: new ActionExecutor({ adapter }),
    });

    expect(handler.isBlocking()).toBe(false);

    const out = await handler.handlePreToolUse({
      hook: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { content: MARKER },
    } as HookInput);

    // The internal ATR verdict is unchanged — advisory mode changes what is
    // EMITTED to the host, not what ATR concluded.
    expect(out.decision).toBe('deny');
    expect(out.matched_rules).toContain('ATR-2026-09101');

    const payload = toClaudeCodePreToolUse(out, { blocking: handler.isBlocking() });
    expect(payload['hookSpecificOutput']).toBeUndefined();
    expect(JSON.stringify(payload)).not.toContain('permissionDecision');
  });

  it('picks blocking up from ATR_BLOCKING', async () => {
    process.env['ATR_BLOCKING'] = 'true';
    const engine = await loadedEngine();
    const handler = new HookHandler({
      engine,
      executor: new ActionExecutor({ adapter: new RecordingAdapter() }),
    });
    expect(handler.isBlocking()).toBe(true);
  });

  it('a fail-closed guard error still emits no permissionDecision while advisory', async () => {
    const brokenEngine = {
      evaluateWithVerdict: vi.fn(async () => {
        throw new Error('engine crashed');
      }),
    } as unknown as ATREngine;
    const handler = new HookHandler({
      engine: brokenEngine,
      executor: new ActionExecutor({ adapter: new RecordingAdapter() }),
      failOpen: false,
    });

    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const out = await handler.handlePreToolUse({
      hook: 'PreToolUse',
      tool_name: 'Read',
      tool_input: {},
    } as HookInput);
    stderrSpy.mockRestore();

    // fail-closed still produces a deny internally...
    expect(out.decision).toBe('deny');
    // ...and advisory mode still refuses to vote on permission. "Do not block"
    // means do not block, including when the guard itself is broken.
    const payload = toClaudeCodePreToolUse(out, { blocking: handler.isBlocking() });
    expect(JSON.stringify(payload)).not.toContain('permissionDecision');
  });
});

// --- 6. CLI: the shipping surface ------------------------------------------

describe('atr guard CLI', () => {
  const RULE_YAML = `title: "Enforcement CLI fixture"
id: ATR-2026-09102
rule_version: 1
status: experimental
description: "Fixture rule for the enforcement CLI tests."
author: "ATR Community"
date: "2026/08/14"
schema_version: "0.1"
maturity: test
severity: critical
tags:
  category: excessive-autonomy
  subcategory: fixture
  scan_target: both
  confidence: high
agent_source:
  type: tool_call
  framework: [any]
  provider: [any]
detection:
  method: pattern
  condition: any
  conditions:
    - field: content
      operator: regex
      value: "${MARKER}"
      description: "fixture"
response:
  actions: [block_tool, alert]
  message_template: "fixture"
test_cases:
  true_positives:
    - input: "${MARKER}"
      expected: triggered
  true_negatives:
    - input: "nothing to see"
      expected: not_triggered
`;

  function runGuard(
    args: readonly string[],
    env: Record<string, string> = {}
  ): { status: number; lines: Array<Record<string, unknown>>; stderr: string } {
    const dir = mkdtempSync(join(tmpdir(), 'atr-enforcement-'));
    try {
      const rulesDir = join(dir, 'rules', 'excessive-autonomy');
      mkdirSync(rulesDir, { recursive: true });
      writeFileSync(join(rulesDir, 'ATR-2026-09102-fixture.yaml'), RULE_YAML);

      const r = spawnSync(
        'npx',
        ['tsx', CLI, 'guard', '--rules', join(dir, 'rules'), ...args],
        {
          encoding: 'utf8',
          timeout: 120_000,
          input: JSON.stringify({
            hook: 'PreToolUse',
            tool_name: 'Read',
            tool_input: { content: MARKER },
          }) + '\n',
          env: { ...process.env, ...env },
        }
      );
      const lines = (r.stdout ?? '')
        .split('\n')
        .filter((l) => l.trim().startsWith('{'))
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      return { status: r.status ?? -1, lines, stderr: r.stderr ?? '' };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  const hso = (line: Record<string, unknown>) =>
    (line['hookSpecificOutput'] ?? {}) as Record<string, unknown>;

  it('is advisory by default: detection reported, no permissionDecision', () => {
    const { status, lines, stderr } = runGuard([]);
    expect(status, stderr).toBe(0);
    expect(lines).toHaveLength(1);
    // CONTROL: the fixture rule must have matched, or "no decision" would be
    // trivially true because nothing was detected.
    expect(lines[0]!['matched_rules']).toEqual(['ATR-2026-09102']);
    expect(lines[0]!['atr_decision']).toBe('deny');
    expect(lines[0]!['hookSpecificOutput']).toBeUndefined();
    expect(hso(lines[0]!)['permissionDecision']).toBeUndefined();
    expect(stderr).toContain('blocking=off');
  });

  it('--blocking turns the decision on', () => {
    const { status, lines, stderr } = runGuard(['--blocking']);
    expect(status, stderr).toBe(0);
    expect(lines[0]!['matched_rules']).toEqual(['ATR-2026-09102']);
    expect(hso(lines[0]!)['permissionDecision']).toBe('deny');
    expect(stderr).toContain('blocking=on');
  });

  it('ATR_BLOCKING turns it on without a flag', () => {
    const { status, lines } = runGuard([], { ATR_BLOCKING: '1' });
    expect(status).toBe(0);
    expect(hso(lines[0]!)['permissionDecision']).toBe('deny');
  });

  it('--no-blocking beats ATR_BLOCKING', () => {
    const { status, lines } = runGuard(['--no-blocking'], { ATR_BLOCKING: '1' });
    expect(status).toBe(0);
    expect(hso(lines[0]!)['permissionDecision']).toBeUndefined();
    expect(lines[0]!['matched_rules']).toEqual(['ATR-2026-09102']);
  });

  it('--lane enforce keeps a maturity=test rule from firing at all', () => {
    const { status, lines, stderr } = runGuard(['--lane', 'enforce', '--blocking']);
    expect(status, stderr).toBe(0);
    expect(lines[0]!['matched_rules']).toBeUndefined();
    expect(hso(lines[0]!)['permissionDecision']).toBe('allow');
    expect(stderr).toContain('lane=enforce');
  });

  it('ATR_LANE does the same, and --lane overrides it', () => {
    const viaEnv = runGuard(['--blocking'], { ATR_LANE: 'enforce' });
    expect(viaEnv.stderr).toContain('lane=enforce');
    expect(viaEnv.lines[0]!['matched_rules']).toBeUndefined();

    const flagWins = runGuard(['--lane', 'hunt', '--blocking'], { ATR_LANE: 'enforce' });
    expect(flagWins.stderr).toContain('lane=hunt');
    expect(flagWins.lines[0]!['matched_rules']).toEqual(['ATR-2026-09102']);
  });

  it('rejects a misspelled lane instead of quietly running in hunt', () => {
    const { status, stderr } = runGuard(['--lane', 'enfroce']);
    expect(status).toBe(1);
    expect(stderr + '').toContain('Invalid --lane');
  });

  it('rejects contradictory blocking flags', () => {
    const { status, stderr } = runGuard(['--blocking', '--no-blocking']);
    expect(status).toBe(1);
    expect(stderr).toContain('mutually exclusive');
  });
});

describe('ambient environment must not crash a library constructor', () => {
  // A stray ATR_BLOCKING=enabled used to exit the guard with status 1 and an
  // empty stdout -- landing hardest on the operator who was trying to turn
  // enforcement ON. A typo'd ATR_LANE crashed the VS Code extension from the
  // ATREngine constructor. Neither process asked to read the environment.
  //
  // The throwing resolvers stay for explicit arguments, which are the caller's
  // own bug. The OrWarn wrappers exist for the ambient case: loud on stderr,
  // safe default, process survives. Loud is what keeps this from being the
  // silent fallback the throwing version exists to prevent.
  beforeEach(() => resetEnforcementWarnings());

  it('an unparseable ATR_LANE warns and falls back instead of throwing', () => {
    const seen: string[] = [];
    const write = process.stderr.write;
    (process.stderr as { write: unknown }).write = (chunk: string) => {
      seen.push(String(chunk));
      return true;
    };
    try {
      expect(resolveLaneOrWarn(undefined, { ATR_LANE: 'enfroce' })).toBe('hunt');
    } finally {
      (process.stderr as { write: unknown }).write = write;
    }
    expect(seen.join('')).toContain('enfroce');
  });

  it('an unparseable ATR_BLOCKING warns and falls back to off', () => {
    const seen: string[] = [];
    const write = process.stderr.write;
    (process.stderr as { write: unknown }).write = (chunk: string) => {
      seen.push(String(chunk));
      return true;
    };
    try {
      expect(resolveBlockingOrWarn(undefined, { ATR_BLOCKING: 'enabled' })).toBe(false);
    } finally {
      (process.stderr as { write: unknown }).write = write;
    }
    // The operator asked for enforcement and is not getting it. Say so.
    expect(seen.join('')).toContain('NOT enabled');
  });

  it('an explicit bad argument still throws -- that is the caller, not the shell', () => {
    expect(() => resolveLaneOrWarn('enfroce')).toThrow(TypeError);
  });

  it('constructing an engine under a typo\'d ATR_LANE does not throw', () => {
    expect(() => new ATREngine({ rulesDir: 'rules' })).not.toThrow();
  });

  it('the warning is emitted once per distinct value, not per call', () => {
    let calls = 0;
    const write = process.stderr.write;
    (process.stderr as { write: unknown }).write = () => {
      calls += 1;
      return true;
    };
    try {
      for (let i = 0; i < 5; i += 1) {
        resolveBlockingOrWarn(undefined, { ATR_BLOCKING: 'enabled' });
      }
    } finally {
      (process.stderr as { write: unknown }).write = write;
    }
    expect(calls).toBe(1);
  });
});
