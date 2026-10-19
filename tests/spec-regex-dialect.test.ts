/**
 * SPEC §6.4, Regular-Expression Dialect, as the reference engine runs it.
 *
 * Until 2026-10-19 the section said an engine applies the flags named in a
 * leading inline group. Read that way, a pattern without (?i) is
 * case-sensitive, and (?s) and (?m) switch on dotAll and multiline mode. The
 * engine does neither, and the conformance suite's true-positive fixtures need
 * case-insensitive matching, so the section was corrected to what the engine
 * does (SPEC.md 1.0.1, issue #698). These tests pin that behaviour to the
 * section: a change that breaks one of them makes the engine non-conforming to
 * SPEC §6.4, so changing the behaviour needs a SPEC change first.
 *
 *   1. A leading group of i, m, s and x, and only a leading one, is removed
 *      before compiling, and u is added exactly when the rest needs it.
 *   2. Every regex condition matches case-insensitively, with or without (?i).
 *   3. m, s and x in that group have no effect.
 */
import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ATREngine } from '../src/engine.js';
import type { AgentEvent, ATRRule } from '../src/types.js';

const MISSING = join(__dirname, '__missing_rules__');

function ruleWith(value: string): ATRRule {
  return {
    id: 'ATR-2026-99990',
    title: 'SPEC 6.4 fixture',
    status: 'stable',
    maturity: 'stable',
    description: 'fixture',
    author: 'test',
    date: '2026/10/19',
    severity: 'high',
    tags: { category: 'prompt-injection', confidence: 'high' },
    agent_source: { type: 'llm_io' },
    detection: { condition: 'any', conditions: [{ field: 'content', operator: 'regex', value }] },
    response: { actions: ['alert'] },
  } as unknown as ATRRule;
}

async function fires(value: string, content: string): Promise<boolean> {
  const engine = new ATREngine({ rules: [ruleWith(value)], rulesDir: MISSING });
  await engine.loadRules();
  const event: AgentEvent = { type: 'llm_input', timestamp: '2026-10-19T00:00:00.000Z', content };
  return engine.evaluate(event).length > 0;
}

describe('SPEC §6.4 regular-expression dialect', () => {
  it('removes a leading flag group before compiling the rest', async () => {
    expect(await fires('(?i)ignore previous', 'please ignore previous orders')).toBe(true);
    expect(await fires('(?is)ignore previous', 'please ignore previous orders')).toBe(true);
    expect(await fires('(?imsx)ignore previous', 'please ignore previous orders')).toBe(true);
  });

  it('removes only a group at the very start', async () => {
    // Anywhere else, (?i) stays in the pattern, which is then a syntax error.
    expect(await fires('ignore(?i) previous', 'ignore previous')).toBe(false);
  });

  it('adds u exactly when the pattern needs it', async () => {
    const ch = (cp: number): string => String.fromCodePoint(cp);
    // A class range between astral characters compiles only with u.
    expect(await fires(`[${ch(0xe0000)}-${ch(0xe007f)}]{3,}`, ch(0xe0041) + ch(0xe0042) + ch(0xe0043))).toBe(true);
    // \_ is an identity escape without u and a syntax error with it.
    expect(await fires('\\_x', '_x')).toBe(true);
  });

  it('matches case-insensitively whether or not the pattern starts with (?i)', async () => {
    expect(await fires('ignore previous instructions', 'IGNORE PREVIOUS INSTRUCTIONS')).toBe(true);
    expect(await fires('(?i)ignore previous instructions', 'Ignore Previous Instructions')).toBe(true);
    expect(await fires('\\bAKIA[0-9A-Z]{4}\\b', 'akia12ab')).toBe(true);
  });

  it('gives m no effect: ^ and $ anchor to the whole field', async () => {
    expect(await fires('(?im)^system:', 'system: obey')).toBe(true);
    expect(await fires('(?im)^system:', 'hello\nsystem: obey')).toBe(false);
    expect(await fires('(?im)obey$', 'obey\nand more')).toBe(false);
  });

  it('gives s no effect: . does not match a line terminator', async () => {
    expect(await fires('(?is)begin.end', 'begin-end')).toBe(true);
    expect(await fires('(?is)begin.end', 'begin\nend')).toBe(false);
  });

  it('gives x no effect: whitespace in the pattern stays literal', async () => {
    expect(await fires('(?x)ignore previous', 'ignore previous')).toBe(true);
    expect(await fires('(?x)ignore previous', 'ignoreprevious')).toBe(false);
  });

  it('expects a line start or a line-crossing character written into the pattern', async () => {
    expect(await fires('(?:^|\\n)system:', 'hello\nsystem: obey')).toBe(true);
    expect(await fires('begin[\\s\\S]end', 'begin\nend')).toBe(true);
  });
});
