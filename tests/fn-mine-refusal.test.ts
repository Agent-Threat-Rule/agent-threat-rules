/**
 * Tests for scripts/lib/fn-mine-refusal.ts. Run 42526623466 skipped
 * cyberseceval-pi and k8s-resource-pi whole because the model declined their
 * first chunk.
 */
import { describe, it, expect } from 'vitest';
import { isRefusal, isTimeout, mineRefusalSafe, refusalModels } from '../scripts/lib/fn-mine-refusal.js';
import type { ChunkResult } from '../scripts/lib/fn-mine-reply.js';

const REFUSED = new Error("claude CLI exited 1: API Error: Sonnet 5 can't help with this. Start a new session to continue.");
const cand = (cluster: string) => ({ cluster, regex: 'x', category: 'prompt-injection', rationale: 'r' });

describe('isRefusal', () => {
  it('tells a refusal from other failures', () => {
    expect(isRefusal(REFUSED)).toBe(true);
    expect(isRefusal(new Error('claude CLI timed out after 600000ms'))).toBe(false);
    expect(isRefusal(new Error('claude CLI exited 1: rate limited'))).toBe(false);
  });
});

describe('mineRefusalSafe', () => {
  const texts = Array.from({ length: 32 }, (_, i) => `t${i}`);

  it('returns the first model that answers', async () => {
    const asked: string[] = [];
    const r = await mineRefusalSafe(texts, async (_t, m) => {
      asked.push(m);
      if (m === 'a') throw REFUSED;
      return { candidates: [cand('c')], read: true } as ChunkResult;
    }, ['a', 'b'], () => {});
    expect(asked).toEqual(['a', 'b']);
    expect(r).toMatchObject({ dropped: 0, refusals: 1, read: true });
    expect(r.candidates.map((c) => c.cluster)).toEqual(['c']);
  });

  it('splits a chunk every model declines and drops only the pieces still declined', async () => {
    const poison = new Set(['t5']);
    const r = await mineRefusalSafe(texts, async (t) => {
      if (t.some((x) => poison.has(x))) throw REFUSED;
      return { candidates: [cand(t[0])], read: true } as ChunkResult;
    }, ['a'], () => {}, 4);
    expect(r.dropped).toBe(4);
    expect(r.candidates.length).toBeGreaterThan(1);
    expect(r.read).toBe(true);
  });

  it('returns a chunk every model timed out on as unread, not as a failed corpus', async () => {
    const r = await mineRefusalSafe(texts, async () => { throw new Error('claude CLI timed out after 600000ms'); }, ['a', 'b'], () => {});
    expect(r).toMatchObject({ candidates: [], read: false, dropped: 0 });
    expect(isTimeout(new Error('claude CLI timed out after 600000ms'))).toBe(true);
  });

  it('rethrows anything that is not a refusal', async () => {
    await expect(mineRefusalSafe(texts, async () => { throw new Error('boom'); }, ['a'], () => {})).rejects.toThrow('boom');
  });
});

describe('refusalModels', () => {
  it('asks the run model first, then the fallbacks, without repeats', () => {
    expect(refusalModels('m1', { ATR_FNMINE_FALLBACK_MODELS: 'm2, m1 ,m3' })).toEqual(['m1', 'm2', 'm3']);
    expect(refusalModels('m1', {})).toEqual(['m1', 'claude-opus-5-5']);
  });
});
