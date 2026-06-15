import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ATREngine } from '../src/engine.js';
import type { ATRRule, AgentEvent } from '../src/types.js';

const MISSING = join(__dirname, '__missing_rules__');
const evt = (content: string): AgentEvent => ({ type: 'llm_input', timestamp: new Date().toISOString(), content });

function rule(id: string, maturity: string, opts: { confirm?: boolean } = {}): ATRRule {
  return {
    title: id, id, status: 'stable', description: 'test rule',
    author: 'test', date: '2026/06/15', severity: 'high', maturity,
    ...(opts.confirm ? { confirm: 'embedding' } : {}),
    tags: { category: 'prompt-injection', confidence: 'high' },
    agent_source: { type: 'llm_io' },
    detection: { conditions: [{ field: 'content', operator: 'regex', value: 'attackpattern' }], condition: 'any' },
    response: { actions: ['alert'] },
  } as unknown as ATRRule;
}

async function mk(rules: ATRRule[], cfg: Record<string, unknown> = {}): Promise<ATREngine> {
  const e = new ATREngine({ rules, rulesDir: MISSING, ...cfg });
  await e.loadRules();
  return e;
}

// Minimal embedding module stub: returns a fixed similarity.
function mockEmb(sim: number) {
  return {
    isAvailable: () => true,
    evaluate: async (_e: unknown, sig: { threshold?: number }) => ({
      matched: sim >= (sig.threshold ?? 0.65), value: sim, description: 'mock',
    }),
  } as never;
}

describe('lane gate', () => {
  const rules = (): ATRRule[] => [
    rule('ATR-2026-90001', 'stable'),
    rule('ATR-2026-90002', 'test'),
    rule('ATR-2026-90003', 'experimental'),
  ];

  it('default (unset lane) fires all maturities — backward compatible', async () => {
    const e = await mk(rules());
    expect(e.evaluate(evt('attackpattern')).length).toBe(3);
  });
  it('hunt lane fires all maturities', async () => {
    const e = await mk(rules(), { lane: 'hunt' });
    expect(e.evaluate(evt('attackpattern')).length).toBe(3);
  });
  it('alert lane fires stable + test only', async () => {
    const e = await mk(rules(), { lane: 'alert' });
    expect(e.evaluate(evt('attackpattern')).map((m) => m.rule.id).sort())
      .toEqual(['ATR-2026-90001', 'ATR-2026-90002']);
  });
  it('enforce lane fires stable only', async () => {
    const e = await mk(rules(), { lane: 'enforce' });
    expect(e.evaluate(evt('attackpattern')).map((m) => m.rule.id)).toEqual(['ATR-2026-90001']);
  });
});

describe('embedding-confirm gate', () => {
  const confirmRule = (): ATRRule[] => [rule('ATR-2026-90010', 'stable', { confirm: true })];
  const fired = (v: { matches: { rule: { id: string } }[] }) => v.matches.some((m) => m.rule.id === 'ATR-2026-90010');

  it('keeps a confirm rule when similarity >= threshold (enforce)', async () => {
    const e = await mk(confirmRule(), { lane: 'enforce', embeddingModule: mockEmb(0.9), confirmThreshold: 0.6 });
    const { verdict } = await e.evaluateWithVerdict(evt('attackpattern'));
    expect(fired(verdict)).toBe(true);
  });
  it('drops a confirm rule when similarity < threshold (enforce)', async () => {
    const e = await mk(confirmRule(), { lane: 'enforce', embeddingModule: mockEmb(0.3), confirmThreshold: 0.6 });
    const { verdict } = await e.evaluateWithVerdict(evt('attackpattern'));
    expect(fired(verdict)).toBe(false);
  });
  it('drops a confirm rule in enforce when no embedding module is configured', async () => {
    const e = await mk(confirmRule(), { lane: 'enforce' });
    const { verdict } = await e.evaluateWithVerdict(evt('attackpattern'));
    expect(fired(verdict)).toBe(false);
  });
  it('fires a confirm rule unconditionally in the hunt lane (no confirmation required)', async () => {
    const e = await mk(confirmRule(), { lane: 'hunt' });
    const { verdict } = await e.evaluateWithVerdict(evt('attackpattern'));
    expect(fired(verdict)).toBe(true);
  });

  it('alert lane: keeps confirm rule when similarity >= threshold', async () => {
    const e = await mk(confirmRule(), { lane: 'alert', embeddingModule: mockEmb(0.9), confirmThreshold: 0.6 });
    expect(fired((await e.evaluateWithVerdict(evt('attackpattern'))).verdict)).toBe(true);
  });
  it('alert lane: drops confirm rule when similarity < threshold', async () => {
    const e = await mk(confirmRule(), { lane: 'alert', embeddingModule: mockEmb(0.3), confirmThreshold: 0.6 });
    expect(fired((await e.evaluateWithVerdict(evt('attackpattern'))).verdict)).toBe(false);
  });
});

describe('confirm gate — sync vs async, precedence, edge cases', () => {
  const fired = (v: { matches: { rule: { id: string } }[] }, id: string) => v.matches.some((m) => m.rule.id === id);

  it('sync evaluate() EXCLUDES confirm rules in enforce (cannot confirm synchronously)', async () => {
    const e = await mk([rule('ATR-2026-90010', 'stable', { confirm: true })], { lane: 'enforce' });
    expect(e.evaluate(evt('attackpattern')).length).toBe(0);
  });
  it('sync evaluate() INCLUDES confirm rules in hunt', async () => {
    const e = await mk([rule('ATR-2026-90010', 'stable', { confirm: true })], { lane: 'hunt' });
    expect(e.evaluate(evt('attackpattern')).length).toBe(1);
  });
  it('lane filter takes priority: an experimental+confirm rule never reaches the confirm gate in enforce', async () => {
    const e = await mk([rule('ATR-2026-90011', 'experimental', { confirm: true })], { lane: 'enforce', embeddingModule: mockEmb(0.99), confirmThreshold: 0.6 });
    expect(fired((await e.evaluateWithVerdict(evt('attackpattern'))).verdict, 'ATR-2026-90011')).toBe(false);
  });
  it('confirmThreshold 0 disables the gate (confirm rule survives at low similarity)', async () => {
    const e = await mk([rule('ATR-2026-90010', 'stable', { confirm: true })], { lane: 'enforce', embeddingModule: mockEmb(0.1), confirmThreshold: 0 });
    expect(fired((await e.evaluateWithVerdict(evt('attackpattern'))).verdict, 'ATR-2026-90010')).toBe(true);
  });
  it('enforce EXCLUDES the additive embedding-only signal (no block from embedding alone)', async () => {
    const e = await mk([rule('ATR-2026-90020', 'stable')], { lane: 'enforce', embeddingModule: mockEmb(0.97) });
    const { verdict } = await e.evaluateWithVerdict(evt('benign text with no matching pattern'));
    expect(verdict.matchCount).toBe(0);
  });
  it('hunt INCLUDES the additive embedding-only signal', async () => {
    const e = await mk([rule('ATR-2026-90020', 'stable')], { lane: 'hunt', embeddingModule: mockEmb(0.97) });
    const { verdict } = await e.evaluateWithVerdict(evt('benign text with no matching pattern'));
    expect(fired(verdict, 'tier2.5-embedding-match')).toBe(true);
  });
});
