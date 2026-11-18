import { describe, expect, it } from 'vitest';
// @ts-expect-error -- plain ESM script without type declarations
import { loadAllowlist, offends, scan } from '../scripts/check-vendor-mentions.mjs';

const TODAY = '2026-11-18';

describe('offends', () => {
  it('flags the two mentions this check was written after', () => {
    expect(offends('網頁版報告：https://panguard.ai/research/96k-scan')).toBe(true);
    expect(offends('- **244 commits are authored as `Panguard AI <support@panguard.ai>`.**')).toBe(true);
  });

  it('flags informal company names and product domains', () => {
    expect(offends('organization: ATR Project / Panguard AI, Inc.')).toBe(true);
    expect(offends("const TC_URL = 'https://tc.panguard.ai';")).toBe(true);
    expect(offends('npm i @panguard-ai/guard')).toBe(true);
  });

  it('allows a disclosure that uses only the legal name', () => {
    expect(offends('Interests: the maintainer founded and controls PANGUARD AI, INC., which sells products.')).toBe(false);
  });

  it('still flags a disclosure line that also carries a link', () => {
    expect(offends('PANGUARD AI, INC. — see https://panguard.ai')).toBe(true);
  });

  it('flags vendor product names even without the company name', () => {
    expect(offends('Synced to Threat Cloud for distribution')).toBe(true);
    expect(offends('author: "ATR Threat Cloud Crystallization"')).toBe(true);
    expect(offends('| **Framework** | ATR Skill Auditor (Node.js, batch mode) |')).toBe(true);
    expect(offends('wraps the engine in a `GuardATREngine` class')).toBe(true);
  });

  it('leaves the neutral names and generic prose alone', () => {
    expect(offends('author: "ATR Community Feed Crystallization"')).toBe(false);
    expect(offends('This is the asset shape a skill auditor sees before anything runs.')).toBe(false);
  });

  it('does not match words that merely contain the letters', () => {
    expect(offends('SpanGuard: Decoupling Instruction Localization')).toBe(false);
  });
});

describe('scan with an allowlist', () => {
  const files = { 'a.md': 'ok\nsee https://panguard.ai\n', 'b.md': 'PANGUARD AI, INC. disclosure\n' };
  const read = (p: string) => files[p as keyof typeof files];

  it('reports path and line for each violation', () => {
    const { entries } = loadAllowlist('{"entries": []}', TODAY);
    expect(scan(Object.keys(files), read, entries)).toEqual(['a.md:2: see https://panguard.ai']);
  });

  it('accepts an allow-listed line and marks the entry used', () => {
    const { entries } = loadAllowlist(
      JSON.stringify({ entries: [{ path: 'a.md', contains: 'panguard.ai', reason: 'x', expires: '2027-01-01' }] }),
      TODAY,
    );
    expect(scan(Object.keys(files), read, entries)).toEqual([]);
    expect(entries[0].used).toBe(true);
  });

  it('rejects expired entries and entries without a reason', () => {
    const { problems } = loadAllowlist(
      JSON.stringify({
        entries: [
          { path: 'a.md', contains: 'x', reason: 'y', expires: '2026-01-01' },
          { path: 'a.md', contains: 'x', expires: '2027-01-01' },
        ],
      }),
      TODAY,
    );
    expect(problems).toHaveLength(2);
  });
});
