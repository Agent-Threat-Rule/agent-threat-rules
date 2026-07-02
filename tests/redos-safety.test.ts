import { describe, it, expect, beforeAll } from 'vitest';
import { join } from 'node:path';
import { isReDoSSafe, ATREngine } from '../src/engine.js';

/**
 * ReDoS safety gate (findings #7 / #22 / #26).
 *
 * A synchronous RegExp cannot be interrupted mid-match on Node's single thread,
 * so the hook-handler timeout can never abort a catastrophic-backtracking rule.
 * The only effective defense is refusing to compile the dangerous pattern at
 * load time. These tests lock in three properties:
 *   1. Textbook exponential forms ARE rejected.
 *   2. Real corpus shapes that only LOOK nested (disjoint multi-atom groups,
 *      bounded repetition) are NOT rejected — no silent detection regression.
 *   3. The full bundled rule corpus compiles with zero ReDoS rejections, and
 *      an actually-catastrophic pattern would have hung where the corpus does not.
 */
describe('ReDoS safety gate', () => {
  it('rejects textbook exponential (single-atom nested quantifier)', () => {
    for (const bad of [
      '(a+)+',
      '(a*)*',
      '([a-z]+)*',
      '(\\w+)+',
      '(.*)*',
      '(\\d+)+$',
      '(a|a)+',
      '.*.*.*.*',
    ]) {
      expect(isReDoSSafe(bad), `should reject ${bad}`).toBe(false);
    }
  });

  it('does NOT reject safe shapes that merely resemble nesting', () => {
    for (const ok of [
      // disjoint multi-atom group — one parse per iteration, linear
      '(?:-\\S+\\s+)*https?://',
      '(\\S+\\s+)*',
      '(-[sSfLo]+\\s+)*',
      // bounded outer repetition — polynomial, not exponential
      '(?:\\w+\\s+){0,3}',
      '(?:\\w+\\s+){40,}',
      // ordinary alternation, no nested quantifier
      '(;|&&|\\|\\|)\\s*(whoami|id)',
      'curl\\s+https?://evil\\.com',
    ]) {
      expect(isReDoSSafe(ok), `should accept ${ok}`).toBe(true);
    }
  });

  it('compiles the full bundled corpus with zero ReDoS rejections', async () => {
    const rejected: string[] = [];
    const origWarn = console.warn;
    console.warn = (...a: unknown[]) => {
      const s = a.join(' ');
      if (s.includes('ReDoS-unsafe')) rejected.push(s);
      else origWarn(...(a as []));
    };
    try {
      const engine = new ATREngine({ rulesDir: join(process.cwd(), 'rules') });
      const count = await engine.loadRules();
      expect(count).toBeGreaterThan(100);
    } finally {
      console.warn = origWarn;
    }
    expect(rejected, `rejected: ${rejected.join('\n')}`).toHaveLength(0);
  });

  it('a rejected pattern would in fact backtrack catastrophically (the gate earns its keep)', () => {
    // Prove the danger is real: (a+)+$ against a long non-matching run is the
    // classic exponential blow-up. We only run it at a length small enough to
    // stay bounded, but large enough that a linear engine finishes instantly
    // while the vulnerable form takes measurable time — then confirm the gate
    // rejects it so it can never be compiled.
    const evil = '(a+)+$';
    expect(isReDoSSafe(evil)).toBe(false);
    const re = new RegExp(evil);
    // Length 20 keeps the demo bounded (~2^20 backtracks, tens of ms) so CI
    // stays fast, while still measurably slow — proof the shape is dangerous.
    const bait = 'a'.repeat(20) + '!';
    const t0 = process.hrtime.bigint();
    re.test(bait);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    expect(ms).toBeGreaterThan(1);
  });
});
