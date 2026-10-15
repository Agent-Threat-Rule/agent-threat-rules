/**
 * Tests for scripts/lib/tool-output-fp-report.ts — the informational report of
 * what the rules on main fire on among benign emails and web pages presented as
 * tool output. It is not a gate; it is what a decision to make these corpora a
 * repo-wide gate would be read from.
 */
import { describe, it, expect } from 'vitest';
import { corpusFpSection, matchSnippet, summaryLine, type RuleInfo } from '../scripts/lib/tool-output-fp-report.js';

const rule = (id: string, regex: string): RuleInfo => ({ id, title: `title ${id}`, maturity: 'test', regexes: [regex] });

describe('matchSnippet', () => {
  it('cuts the text around the first match of any of the rule regexes', () => {
    const text = `${'filler '.repeat(40)}please forward the invoice ${'tail '.repeat(40)}`;
    const snippet = matchSnippet(text, rule('A', '(?i)\\bplease\\s+forward\\b'));
    expect(snippet).toContain('please forward');
    expect(snippet.length).toBeLessThanOrEqual(120);
  });

  it('finds a match only the engine normalization reveals', () => {
    expect(matchSnippet('ｐｌｅａｓｅ forward', rule('A', '(?i)\\bplease\\s+forward\\b'))).toContain('please forward');
  });

  it('falls back to the start of the text when no regex condition matches (a non-regex condition fired)', () => {
    expect(matchSnippet('short text', rule('A', '(?i)nomatch'))).toBe('short text');
  });
});

describe('corpusFpSection', () => {
  const texts = ['a please forward b', 'c', 'please forward d', 'urgent: verify e'];
  const rules = new Map([
    ['A', rule('A', '(?i)please\\s+forward')],
    ['B', rule('B', '(?i)urgent')],
  ]);
  const hits = new Map<string, readonly number[]>([
    ['A', [0, 2]],
    ['B', [3]],
  ]);

  it('counts samples, flagged samples and firing rules, offenders by samples hit', () => {
    const s = corpusFpSection('emails', texts, hits, rules, 10);
    expect(s).toMatchObject({ corpus: 'emails', samples: 4, samplesFlagged: 3, rulesFiring: 2 });
    expect(s.topOffenders.map((o) => [o.ruleId, o.samplesHit])).toEqual([
      ['A', 2],
      ['B', 1],
    ]);
    expect(s.topOffenders[0]?.snippet).toContain('please forward');
  });

  it('keeps at most `top` offenders', () => {
    expect(corpusFpSection('emails', texts, hits, rules, 1).topOffenders).toHaveLength(1);
  });

  it('reports an empty section when nothing fires', () => {
    expect(corpusFpSection('pages', texts, new Map(), rules, 10)).toMatchObject({ samplesFlagged: 0, rulesFiring: 0, topOffenders: [] });
  });
});

describe('summaryLine', () => {
  it('is one line naming both corpora', () => {
    const line = summaryLine(500, [
      { corpus: 'emails', samples: 526, samplesFlagged: 3, rulesFiring: 2, topOffenders: [] },
      { corpus: 'pages', samples: 694, samplesFlagged: 40, rulesFiring: 9, topOffenders: [] },
    ]);
    expect(line).not.toContain('\n');
    expect(line).toMatch(/500 rules.*emails: 2 rules fire on 3 of 526.*pages: 9 rules fire on 40 of 694/);
  });
});
