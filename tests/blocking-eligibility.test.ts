/**
 * Blocking is opt-in everywhere, and once it is on only a blocking-eligible
 * match may block: a live rule the enforce lane admits (maturity: stable) at
 * severity high or critical, not decided by a model (isBlockingEligible in
 * src/enforcement.ts).
 *
 * WHAT THIS PINS, for every TypeScript surface that can block (the guard hook,
 * the ActionExecutor, the Mastra processor, the openshell-filter and
 * nemoclaw-preflight entry points, `atr scan --fail-on`, the GitHub Action):
 *
 *   defaults                                  -> nothing blocks
 *   blocking on + stable critical / high      -> blocks
 *   blocking on + stable medium               -> does not block (and no "ask")
 *   blocking on + test / experimental critical -> does not block, still reported
 *   blocking on + draft status                -> never fires, never blocks
 *
 * Fixture rules (tests/fixtures/blocking-rules.ts) match harmless markers, so
 * these cases do not move when the real rule set promotes a rule.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import yaml from 'js-yaml';

import {
  BLOCKING_LANE,
  BLOCKING_MIN_SEVERITY,
  BLOCKING_SEVERITIES,
  blockingMatches,
  blockingSeveritiesFrom,
  isBlockingEligible,
  parseBlockingSeverity,
  verdictBlockingMatches,
} from '../src/enforcement.js';
import { ATREngine } from '../src/engine.js';
import { ActionExecutor } from '../src/action-executor.js';
import { HookHandler, toClaudeCodePostToolUse, toClaudeCodePreToolUse } from '../src/hook-handler.js';
import { ATRProcessor, type ATRDetectionReport } from '../src/adapters/mastra.js';
import { OpenShellFilter } from '../src/adapters/openshell-filter.js';
import { NemoClawPreflight } from '../src/adapters/nemoclaw-preflight.js';
import { computeVerdict } from '../src/verdict.js';
import type { ActionResult, ATRMatch, HookInput, PlatformAdapter } from '../src/types.js';
import { FIXTURES, fixtureMatch, fixtureRule, writeBlockingRulesDir } from './fixtures/blocking-rules.js';

const ROOT = new URL('..', import.meta.url).pathname;
const CLI = join(ROOT, 'src', 'cli.ts');

// --- 1. the rule itself ----------------------------------------------------

describe('isBlockingEligible', () => {
  it('admits a live maturity: stable rule at critical or high, nothing else', () => {
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableCritical))).toBe(true);
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableHigh))).toBe(true);
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableMedium))).toBe(false);
    expect(isBlockingEligible(fixtureMatch(FIXTURES.testCritical))).toBe(false);
    expect(isBlockingEligible(fixtureMatch(FIXTURES.experimentalCritical))).toBe(false);
    expect(isBlockingEligible(fixtureMatch(FIXTURES.draftStatusStableCritical))).toBe(false);
  });

  it('reads maturity through the engine lane gate: missing, odd or deprecated never block', () => {
    const base = fixtureMatch(FIXTURES.stableCritical);
    for (const maturity of [undefined, '', 'Stable', 'needs-human-poc', 'deprecated']) {
      const match = { ...base, rule: { ...base.rule, maturity } } as unknown as ATRMatch;
      expect(isBlockingEligible(match), String(maturity)).toBe(false);
    }
    const deprecated = { ...base, rule: { ...base.rule, status: 'deprecated' } } as unknown as ATRMatch;
    expect(isBlockingEligible(deprecated)).toBe(false);
  });

  it('holds back a model-decided match unless modelDecisions is enforce', () => {
    const judged = fixtureMatch(FIXTURES.stableCritical, { decidedBy: 'semantic-judge' });
    expect(isBlockingEligible(judged)).toBe(false);
    expect(isBlockingEligible(judged, { modelDecisions: 'advisory' })).toBe(false);
    expect(isBlockingEligible(judged, { modelDecisions: 'enforce' })).toBe(true);
    // CONTROL: deterministic deciders are unaffected.
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableCritical, { decidedBy: 'pattern' }))).toBe(true);
  });

  it('refuses an unconfirmed confirm: embedding match from a hunt-lane engine', () => {
    const confirmRule = { ...fixtureMatch(FIXTURES.stableCritical) };
    const match = { ...confirmRule, rule: { ...confirmRule.rule, confirm: 'embedding' } } as ATRMatch;
    expect(isBlockingEligible(match)).toBe(false);
    expect(isBlockingEligible(match, { detectionLane: 'hunt' })).toBe(false);
    // An enforce/alert engine only returns it after the embedding confirmation.
    expect(isBlockingEligible(match, { detectionLane: 'enforce' })).toBe(true);
    expect(isBlockingEligible(match, { detectionLane: 'alert' })).toBe(true);
  });

  it('lets a threshold narrow to critical but never widen past high', () => {
    const critical = blockingSeveritiesFrom('critical');
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableHigh), { severities: critical })).toBe(false);
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableCritical), { severities: critical })).toBe(true);
    // A hand-built list that includes medium cannot make medium eligible.
    const widened = ['critical', 'high', 'medium'] as never;
    expect(isBlockingEligible(fixtureMatch(FIXTURES.stableMedium), { severities: widened })).toBe(false);
  });

  it('exports the constants every surface reads', () => {
    expect(BLOCKING_LANE).toBe('enforce');
    expect(BLOCKING_MIN_SEVERITY).toBe('high');
    expect([...BLOCKING_SEVERITIES]).toEqual(['critical', 'high']);
    expect(parseBlockingSeverity(' HIGH ')).toBe('high');
    for (const bad of ['medium', 'low', 'informational', 'hgih', '']) {
      expect(parseBlockingSeverity(bad)).toBeNull();
      expect(() => blockingSeveritiesFrom(bad)).toThrow(/critical, high/);
    }
  });

  it('reads the modelDecisions setting back from a verdict', () => {
    const judged = fixtureMatch(FIXTURES.stableCritical, { decidedBy: 'semantic-judge' });
    const advisory = computeVerdict([judged]);
    const enforce = computeVerdict([judged], { modelDecisions: 'enforce' });
    expect(verdictBlockingMatches(advisory)).toHaveLength(0);
    expect(verdictBlockingMatches(enforce)).toHaveLength(1);
    expect(blockingMatches([judged, fixtureMatch(FIXTURES.stableHigh)])).toHaveLength(1);
  });
});

// --- 2. the guard hook -----------------------------------------------------

class RecordingAdapter implements PlatformAdapter {
  readonly name = 'recording';
  calls: string[] = [];
  private record(method: string, action: string): ActionResult {
    this.calls.push(method);
    return { action: action as ActionResult['action'], success: true, message: method, timestamp: '' };
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

async function engineWithFixtures(sourceType: 'llm_io' | 'mcp_exchange' = 'llm_io'): Promise<ATREngine> {
  const rules = Object.values(FIXTURES).map((f) => fixtureRule(f, undefined, sourceType));
  const engine = new ATREngine({ rules });
  expect(await engine.loadRules()).toBeGreaterThan(0);
  return engine;
}

function hookInput(marker: string, hook = 'PreToolUse'): HookInput {
  return { hook, tool_name: 'Read', tool_input: { content: marker } } as HookInput;
}

describe('HookHandler with blocking on', () => {
  let engine: ATREngine;
  let handler: HookHandler;
  beforeAll(async () => {
    engine = await engineWithFixtures('mcp_exchange');
    const executor = new ActionExecutor({ adapter: new RecordingAdapter(), dryRun: true, blocking: true });
    handler = new HookHandler({ engine, executor, blocking: true });
  });

  const pre = async (marker: string) =>
    toClaudeCodePreToolUse(await handler.handlePreToolUse(hookInput(marker)), { blocking: true });

  it('denies on a stable critical and a stable high match', async () => {
    for (const f of [FIXTURES.stableCritical, FIXTURES.stableHigh]) {
      const p = await pre(f.marker);
      expect((p['hookSpecificOutput'] as Record<string, unknown>)['permissionDecision'], f.id).toBe('deny');
      expect(p['atr_blocking_rules']).toEqual([f.id]);
    }
  });

  it('emits no decision for a test or experimental critical match, and still reports it', async () => {
    for (const f of [FIXTURES.testCritical, FIXTURES.experimentalCritical]) {
      const p = await pre(f.marker);
      expect(JSON.stringify(p), f.id).not.toContain('permissionDecision');
      expect(p['matched_rules']).toEqual([f.id]);
      expect(p['atr_detection']).toBe('deny');
      expect(p['atr_decision']).toBe('allow');
    }
  });

  it('never asks on a stable medium match (the old matrix answered "ask")', async () => {
    const p = await pre(FIXTURES.stableMedium.marker);
    expect(JSON.stringify(p)).not.toContain('permissionDecision');
    expect(p['atr_detection']).toBe('ask');
    expect(p['matched_rules']).toEqual([FIXTURES.stableMedium.id]);
  });

  it('a draft-status rule never fires at all', async () => {
    const out = await handler.handlePreToolUse(hookInput(FIXTURES.draftStatusStableCritical.marker));
    expect(out.matched_rules).toBeUndefined();
    expect(out.decision).toBe('allow');
  });

  it('denies, not asks, on a stable high match below the old 0.8 deny confidence', async () => {
    // HookHandler reads the engine's verdict; feed it one whose stable high match
    // has confidence 0.5, which the historical matrix mapped to "ask".
    const low = fixtureMatch(FIXTURES.stableHigh, { confidence: 0.5 });
    const fake = {
      evaluateWithVerdict: async () => ({ verdict: computeVerdict([low]), actionResults: [], layersUsed: [] }),
      getLane: () => 'hunt',
    } as unknown as ATREngine;
    const h = new HookHandler({ engine: fake, executor: new ActionExecutor({ adapter: new RecordingAdapter() }), blocking: true });
    const out = await h.handlePreToolUse(hookInput('x'));
    expect(computeVerdict([low]).outcome).toBe('ask'); // CONTROL: the old answer
    expect(out.decision).toBe('deny');
  });

  it('PostToolUse blocks only on an eligible match', async () => {
    const post = async (marker: string) =>
      toClaudeCodePostToolUse(await handler.handlePostToolUse(hookInput(marker, 'PostToolUse')), { blocking: true });
    expect((await post(FIXTURES.stableCritical.marker))['decision']).toBe('block');
    expect((await post(FIXTURES.testCritical.marker))['decision']).toBeUndefined();
    expect((await post(FIXTURES.stableMedium.marker))['decision']).toBeUndefined();
  });

  it('by default (blocking off) nothing is emitted, eligible or not', async () => {
    const advisory = new HookHandler({ engine, executor: new ActionExecutor({ adapter: new RecordingAdapter() }) });
    for (const f of Object.values(FIXTURES)) {
      const out = await advisory.handlePreToolUse(hookInput(f.marker));
      const p = toClaudeCodePreToolUse(out, { blocking: advisory.isBlocking() });
      expect(JSON.stringify(p), f.id).not.toContain('permissionDecision');
    }
  });
});

// --- 3. the action channel -------------------------------------------------

describe('ActionExecutor with blocking on', () => {
  const run = async (marker: string, blocking: boolean) => {
    const engine = await engineWithFixtures();
    const adapter = new RecordingAdapter();
    const executor = new ActionExecutor({ adapter, blocking });
    await engine.evaluateWithVerdict(hookEvent(marker), executor);
    return adapter.calls;
  };
  const hookEvent = (marker: string) =>
    ({ type: 'llm_input', timestamp: '', content: marker }) as const;

  it('dispatches block_tool only for a stable high/critical match', async () => {
    expect(await run(FIXTURES.stableCritical.marker, true)).toContain('blockTool');
    expect(await run(FIXTURES.stableHigh.marker, true)).toContain('blockTool');
  });

  it('suppresses it for a hunt-only critical or a stable medium match, keeps observe actions', async () => {
    for (const f of [FIXTURES.testCritical, FIXTURES.experimentalCritical, FIXTURES.stableMedium]) {
      const calls = await run(f.marker, true);
      expect(calls, f.id).toContain('alert');
      expect(calls, f.id).not.toContain('blockTool');
    }
  });

  it('suppresses it for every match by default', async () => {
    const calls = await run(FIXTURES.stableCritical.marker, false);
    expect(calls).toContain('alert');
    expect(calls).not.toContain('blockTool');
  });
});

// --- 4. adapters -----------------------------------------------------------

describe('adapters against fixture rules', () => {
  let rules: ReturnType<typeof writeBlockingRulesDir>;
  beforeAll(() => {
    rules = writeBlockingRulesDir();
  });
  afterAll(() => rules.cleanup());

  class Aborted extends Error {}
  const abort = (reason?: string): never => {
    throw new Aborted(reason);
  };
  const message = (text: string) => ({ content: { parts: [{ type: 'text', text }] } });

  it('Mastra: never aborts by default, and reports every match', async () => {
    const reports: ATRDetectionReport[] = [];
    const proc = new ATRProcessor({ rulesDir: rules.dir, onDetection: (r) => reports.push(r) });
    for (const f of Object.values(FIXTURES)) {
      await expect(proc.processInput({ messages: [message(f.marker)], abort }), f.id).resolves.toHaveLength(1);
    }
    // Every fixture but the draft-status one fired and was reported.
    expect(reports).toHaveLength(Object.values(FIXTURES).length - 1);
    expect(reports.every((r) => !r.blockingEnabled && r.blocking.length === 0)).toBe(true);
  });

  it('Mastra with blocking: aborts on stable high/critical only', async () => {
    const proc = new ATRProcessor({ rulesDir: rules.dir, blocking: true, onDetection: () => {} });
    for (const f of [FIXTURES.stableCritical, FIXTURES.stableHigh]) {
      await expect(proc.processInput({ messages: [message(f.marker)], abort }), f.id).rejects.toThrow(Aborted);
    }
    for (const f of [FIXTURES.stableMedium, FIXTURES.testCritical, FIXTURES.experimentalCritical]) {
      await expect(proc.processInput({ messages: [message(f.marker)], abort }), f.id).resolves.toHaveLength(1);
    }
  });

  it('Mastra: blockSeverities narrows to critical, and rejects anything below high', async () => {
    const proc = new ATRProcessor({ rulesDir: rules.dir, blocking: true, blockSeverities: ['critical'], onDetection: () => {} });
    await expect(proc.processInput({ messages: [message(FIXTURES.stableHigh.marker)], abort })).resolves.toHaveLength(1);
    await expect(proc.processInput({ messages: [message(FIXTURES.stableCritical.marker)], abort })).rejects.toThrow(Aborted);
    for (const bad of [['medium'], ['high', 'low'], ['bogus']]) {
      expect(() => new ATRProcessor({ blockSeverities: bad }), bad.join()).toThrow(/blockSeverities/);
    }
    expect(() => new ATRProcessor({ blocking: 'false' as unknown as boolean })).toThrow(TypeError);
  });

  it('openshell-filter: report-only by default, denies only eligible matches when on', async () => {
    const report = new OpenShellFilter({ direction: 'response', minSeverity: 'high', forensic: false, rulesDir: rules.dir });
    const block = new OpenShellFilter({ direction: 'response', minSeverity: 'high', forensic: false, rulesDir: rules.dir, blocking: true });

    const r = await report.inspect(FIXTURES.stableCritical.marker);
    expect(r).toMatchObject({ decision: 'allow', mode: 'report-only', blockingRuleIds: [] });
    expect(r.findings.map((f) => f['atr.rule_id'])).toEqual([FIXTURES.stableCritical.id]);

    expect((await block.inspect(FIXTURES.stableCritical.marker)).decision).toBe('deny');
    expect((await block.inspect(FIXTURES.stableHigh.marker)).decision).toBe('deny');
    const hunt = await block.inspect(FIXTURES.testCritical.marker);
    expect(hunt.decision).toBe('allow');
    expect(hunt.findings).toHaveLength(1); // reported, not blocking
    // Medium is below the reporting threshold as well as the blocking one.
    expect((await block.inspect(FIXTURES.stableMedium.marker)).decision).toBe('allow');
  });

  it('nemoclaw-preflight: report by default, block only on eligible findings when on', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'atr-preflight-blocking-'));
    try {
      const write = (name: string, marker: string) => {
        const sub = join(dir, name);
        mkdirSync(sub, { recursive: true });
        writeFileSync(join(sub, 'SKILL.md'), `# Skill\n${marker}\n`);
        return sub;
      };
      const stable = write('stable', FIXTURES.stableCritical.marker);
      const hunt = write('hunt', FIXTURES.testCritical.marker);
      const report = new NemoClawPreflight({ minSeverity: 'high', forensic: false, rulesDir: rules.dir });
      const gate = new NemoClawPreflight({ minSeverity: 'high', forensic: false, rulesDir: rules.dir, blocking: true });

      const r = await report.scanBundle(stable);
      expect(r).toMatchObject({ decision: 'report', mode: 'report-only', blockingRuleIds: [] });
      expect(r.findings).toHaveLength(1);
      expect(await gate.scanBundle(stable)).toMatchObject({ decision: 'block', blockingRuleIds: [FIXTURES.stableCritical.id] });
      const h = await gate.scanBundle(hunt);
      expect(h.decision).toBe('pass');
      expect(h.findings).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// --- 5. process entry points: exit codes -----------------------------------

describe('entry-point exit codes', () => {
  let rules: ReturnType<typeof writeBlockingRulesDir>;
  beforeAll(() => {
    rules = writeBlockingRulesDir();
  });
  afterAll(() => rules.cleanup());

  const ENTRY = join(ROOT, 'src', 'adapters', 'openshell-filter.ts');
  const filter = (body: string, env: Record<string, string>) =>
    spawnSync('npx', ['tsx', ENTRY, '--direction', 'response'], {
      input: body,
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, ATR_BLOCKING: '', ATR_MIN_SEVERITY: '', ATR_RULES_DIR: rules.dir, ...env },
    });

  it('openshell-filter exits 0 by default on a stable critical body, 1 with ATR_BLOCKING=1', () => {
    const report = filter(FIXTURES.stableCritical.marker, {});
    expect(report.status, report.stderr).toBe(0);
    expect(JSON.parse(report.stdout)).toMatchObject({ decision: 'allow', mode: 'report-only' });
    const block = filter(FIXTURES.stableCritical.marker, { ATR_BLOCKING: '1' });
    expect(block.status, block.stderr).toBe(1);
    const hunt = filter(FIXTURES.testCritical.marker, { ATR_BLOCKING: '1' });
    expect(hunt.status, hunt.stderr).toBe(0);
  });

  it('openshell-filter exits 2 with a message on ATR_MIN_SEVERITY=low instead of guessing', () => {
    const r = filter(FIXTURES.stableCritical.marker, { ATR_MIN_SEVERITY: 'low', ATR_BLOCKING: '1' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('ATR_MIN_SEVERITY');
  });

  const scan = (marker: string, args: readonly string[]) => {
    const dir = mkdtempSync(join(tmpdir(), 'atr-scan-failon-'));
    try {
      const events = join(dir, 'events.json');
      writeFileSync(events, JSON.stringify([{ type: 'llm_input', timestamp: '2026-11-04T00:00:00Z', content: marker }]));
      return spawnSync('npx', ['tsx', CLI, 'scan', events, '--rules', rules.dir, '--json', ...args], {
        encoding: 'utf8',
        timeout: 120_000,
        env: { ...process.env, ATR_LANE: '', ATR_MODEL_DECISIONS: '' },
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it('atr scan exits 0 without --fail-on, whatever it finds', () => {
    expect(scan(FIXTURES.stableCritical.marker, []).status).toBe(0);
  });

  it('atr scan --fail-on high fails only on a stable high/critical match', () => {
    expect(scan(FIXTURES.stableCritical.marker, ['--fail-on', 'high']).status).toBe(1);
    const hunt = scan(FIXTURES.testCritical.marker, ['--fail-on', 'high']);
    expect(hunt.status, hunt.stderr).toBe(0);
    expect(hunt.stdout).toContain(FIXTURES.testCritical.id); // CONTROL: it was reported
  });

  it('atr scan --fail-on medium is a usage error, not a wider gate', () => {
    const r = scan(FIXTURES.stableMedium.marker, ['--fail-on', 'medium']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--fail-on must be one of: critical, high');
  });
});

// --- 6. the GitHub Action ---------------------------------------------------

describe('action.yml', () => {
  const text = readFileSync(join(ROOT, 'action.yml'), 'utf8');
  const action = yaml.load(text) as {
    inputs: Record<string, { default?: string; description?: string }>;
  };

  it('reports by default: fail-on-finding is false, lane hunt', () => {
    expect(action.inputs['fail-on-finding']?.default).toBe('false');
    expect(action.inputs['lane']?.default).toBe('hunt');
    expect(action.inputs['fail-on-finding']?.description).toMatch(/OFF BY DEFAULT/);
  });

  // The gate fragment is cut out of the shipped file and run under sh with a
  // stub `atr`, so the test exercises the real shell, not a copy of it.
  const gate = /# --- enforce-lane gate \(fail-on-finding\) ---[\s\S]*?# --- end enforce-lane gate ---/.exec(text)?.[0];
  const runGate = (failOnFinding: string, stubStatus: number) => {
    const dir = mkdtempSync(join(tmpdir(), 'atr-action-gate-'));
    try {
      const script =
        `atr() { printf '%s\\n' "$*" > '${dir}/args'; echo 'stub stderr' >&2; return ${stubStatus}; }\n` +
        `ATR_FAIL_ON_FINDING='${failOnFinding}'\nATR_PATH='.'\n${gate}\necho reached-end\n`;
      const r = spawnSync('sh', ['-c', script], { encoding: 'utf8', timeout: 30_000 });
      let args = '';
      try {
        args = readFileSync(join(dir, 'args'), 'utf8');
      } catch {
        args = '';
      }
      return { ...r, args };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it('does not run the gate scan unless fail-on-finding is true', () => {
    expect(gate).toBeDefined();
    const r = runGate('false', 1);
    expect(r.status).toBe(0);
    expect(r.args).toBe('');
    expect(r.stdout).toContain('reached-end');
  });

  it('gates on an enforce-lane, high-threshold scan and fails on its non-zero exit', () => {
    const fail = runGate('true', 1);
    expect(fail.status).toBe(1);
    expect(fail.args).toContain('--lane enforce');
    expect(fail.args).toContain('--fail-on high');
    expect(fail.stdout).toContain('::error::ATR enforce-lane gate failed');

    const pass = runGate('true', 0);
    expect(pass.status).toBe(0);
    expect(pass.stdout).toContain('gate passed');
  });

  it('no longer fails the job on the reporting count', () => {
    expect(text).not.toMatch(/ATR_FAIL_ON_FINDING" = "true" \] && \[ "\$\{THREAT_COUNT\}"/);
  });
});
