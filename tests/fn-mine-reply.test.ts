/**
 * Tests for scripts/lib/fn-mine-reply.ts
 *
 * On 2026-10-06 one mining reply carried a trailing comma, JSON.parse threw in
 * the mining loop, and the scheduled run died after an hour of work, losing a
 * candidate it had already gated. These tests pin one unreadable reply to one
 * skipped chunk, and an all-unreadable run to a failed job.
 */
import { describe, it, expect } from 'vitest';
import {
  assertSomeChunkRead,
  extractBalancedJson,
  mineChunkReply,
  parseMineReply,
  stripTrailingCommas,
} from '../scripts/lib/fn-mine-reply.js';

const CANDIDATE = {
  cluster: 'override-gerund',
  regex: '(?i)\\bignoring\\s+(?:all\\s+)?previous\\s+instructions\\b',
  category: 'prompt-injection',
  rationale: 'Gerund form of the override verb.',
};

// The shape of the 2026-10-06 reply: a comma after the last field of a candidate.
const TRAILING_COMMA_REPLY = `{
  "candidates": [
    {
      "cluster": "override-gerund",
      "regex": "(?i)\\\\bignoring\\\\s+(?:all\\\\s+)?previous\\\\s+instructions\\\\b",
      "category": "prompt-injection",
      "rationale": "Gerund form of the override verb.",
    },
  ]
}`;

describe('stripTrailingCommas', () => {
  it('drops a comma before } or ], across whitespace', () => {
    expect(stripTrailingCommas('{"a": [1, 2, ], "b": 3 ,\n}')).toBe('{"a": [1, 2 ], "b": 3 \n}');
  });

  it('leaves commas inside strings alone, escaped quotes included', () => {
    const json = '{"regex": "a,]b", "note": "say \\",}\\" twice"}';
    expect(stripTrailingCommas(json)).toBe(json);
  });

  it('does not change valid JSON', () => {
    const json = JSON.stringify({ candidates: [CANDIDATE, CANDIDATE] }, null, 2);
    expect(stripTrailingCommas(json)).toBe(json);
  });
});

describe('parseMineReply', () => {
  it('reads the reply that killed the 2026-10-06 run', () => {
    expect(() => JSON.parse(extractBalancedJson(TRAILING_COMMA_REPLY))).toThrow();
    expect(parseMineReply(TRAILING_COMMA_REPLY)).toEqual({ candidates: [CANDIDATE], malformed: 0 });
  });

  it('reads a fenced reply with prose around it', () => {
    const raw = `Here you go:\n\`\`\`json\n${JSON.stringify({ candidates: [CANDIDATE] })}\n\`\`\``;
    expect(parseMineReply(raw).candidates).toEqual([CANDIDATE]);
  });

  it('treats a missing candidates key as the empty answer the prompt allows', () => {
    expect(parseMineReply('{}')).toEqual({ candidates: [], malformed: 0 });
  });

  it('drops and counts entries the gate could not handle, keeping the rest', () => {
    const raw = JSON.stringify({ candidates: [CANDIDATE, { ...CANDIDATE, regex: 42 }, 'loose string', { cluster: 'x' }] });
    expect(parseMineReply(raw)).toEqual({ candidates: [CANDIDATE], malformed: 3 });
  });

  it('throws on a reply broken some other way, or with candidates that is not a list', () => {
    expect(() => parseMineReply('{"candidates": [ {"cluster": unquoted} ]}')).toThrow();
    expect(() => parseMineReply('no json here')).toThrow(/opening brace/);
    expect(() => parseMineReply('{"candidates": "none"}')).toThrow(/not an array/);
  });
});

describe('mineChunkReply', () => {
  const asker = (replies: string[]) => {
    const queue = [...replies];
    let calls = 0;
    return { ask: async () => { calls += 1; return queue.shift() ?? ''; }, calls: () => calls };
  };

  it('asks once when the first reply reads', async () => {
    const a = asker([JSON.stringify({ candidates: [CANDIDATE] })]);
    const warnings: string[] = [];
    const r = await mineChunkReply('pint[0:40]', a.ask, (l) => warnings.push(l));
    expect(r).toEqual({ candidates: [CANDIDATE], read: true });
    expect(a.calls()).toBe(1);
    expect(warnings).toEqual([]);
  });

  it('asks again after an unreadable reply and uses the second', async () => {
    const a = asker(['{"candidates": [ {"cluster": nope} ]}', JSON.stringify({ candidates: [CANDIDATE] })]);
    const warnings: string[] = [];
    const r = await mineChunkReply('pint[0:40]', a.ask, (l) => warnings.push(l));
    expect(r).toEqual({ candidates: [CANDIDATE], read: true });
    expect(a.calls()).toBe(2);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^pint\[0:40\]: reply 1 of 2 is not usable JSON .*; asking again$/);
  });

  it('skips the chunk, without throwing, when no reply reads', async () => {
    const a = asker(['garbage', 'still garbage']);
    const warnings: string[] = [];
    const r = await mineChunkReply('pint[40:80]', a.ask, (l) => warnings.push(l));
    expect(r).toEqual({ candidates: [], read: false });
    expect(warnings[1]).toMatch(/reply 2 of 2 .*; skipping this chunk$/);
  });

  it('lets a failed model call through: that is the lane being down, not a bad reply', async () => {
    const r = mineChunkReply('pint[0:40]', async () => { throw new Error('credit balance is too low'); }, () => {});
    await expect(r).rejects.toThrow(/credit balance/);
  });
});

describe('assertSomeChunkRead', () => {
  it('fails a run in which no reply could be read', () => {
    expect(() => assertSomeChunkRead(4, 4)).toThrow(/none of the 4 mining replies/);
  });

  it('passes a run with at least one readable reply, or nothing to mine', () => {
    expect(() => assertSomeChunkRead(4, 3)).not.toThrow();
    expect(() => assertSomeChunkRead(0, 0)).not.toThrow();
  });
});
