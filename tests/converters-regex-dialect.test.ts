/**
 * The converters translate a regex condition the way SPEC §6.4 defines it:
 * the leading flag group is removed, every condition matches
 * case-insensitively, `m`, `s` and `x` have no effect, and `u` applies when
 * the pattern needs it.
 *
 * Each converter used to follow the group instead (issue #698):
 *   - generic-regex copied its letters into `flags`, so a condition without
 *     (?i) exported flags "" and (?im) turned on multiline in the consumer;
 *   - Splunk passed it to PCRE verbatim, with the same two effects;
 *   - Elastic passed it into a Lucene regexp, which has no inline flags;
 *   - Sage exported a rule as case-sensitive unless a group said (?i).
 */
import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { ruleToGenericRegex } from '../src/converters/generic-regex.js';
import { ruleToSPL } from '../src/converters/splunk.js';
import { ruleToElastic } from '../src/converters/elastic.js';
import { atrToSage, atrToSageBatch } from '../src/converters/sage.js';
import { sageToAtr } from '../src/converters/sage-reverse.js';
import { regexConditionSpec } from '../src/regex-dialect.js';
import { loadRulesFromDirectory } from '../src/loader.js';
import type { ATRRule } from '../src/types.js';

const RULES_DIR = join(__dirname, '..', 'rules');
const ch = (cp: number): string => String.fromCodePoint(cp);
const ASTRAL_CLASS = `[${ch(0xe0000)}-${ch(0xe007f)}]{3,}`;
const VALUES = ['(?i)alpha', 'bravo', '(?im)^charlie', '(?si)delta.echo', '(?x)fox trot'];

function ruleWith(values: readonly string[], condition: 'any' | 'all' = 'any'): ATRRule {
  return {
    id: 'ATR-2026-99980',
    title: 'Regex dialect fixture',
    status: 'experimental',
    maturity: 'test',
    description: 'Fixture for the converters regex dialect tests',
    author: 'test',
    date: '2026/10/19',
    severity: 'high',
    tags: { category: 'prompt-injection', subcategory: 'test', confidence: 'high', scan_target: 'mcp' },
    agent_source: { type: 'llm_io' },
    detection: {
      condition,
      conditions: values.map((value) => ({ field: 'user_input', operator: 'regex', value })),
    },
    response: { actions: ['alert'] },
  } as unknown as ATRRule;
}

describe('generic-regex', () => {
  it('exports the condition without its group, with flags i or iu', () => {
    const out = ruleToGenericRegex(ruleWith([...VALUES, ASTRAL_CLASS]));
    expect(out.patterns.map((p) => [p.regex, p.flags])).toEqual([
      ['alpha', 'i'],
      ['bravo', 'i'],
      ['^charlie', 'i'],
      ['delta.echo', 'i'],
      ['fox trot', 'i'],
      [ASTRAL_CLASS, 'iu'],
    ]);
  });

  it('exports exactly regexConditionSpec() for every corpus condition', () => {
    const mismatches: string[] = [];
    for (const rule of loadRulesFromDirectory(RULES_DIR)) {
      const conditions = (Array.isArray(rule.detection.conditions) ? rule.detection.conditions : []) as Array<{
        operator?: string;
        value?: string;
      }>;
      const expected = conditions
        .filter((c) => c.operator === 'regex' && c.value)
        .map((c) => regexConditionSpec(c.value!));
      const got = ruleToGenericRegex(rule).patterns;
      if (got.length !== expected.length) mismatches.push(`${rule.id}: ${got.length} of ${expected.length}`);
      expected.forEach((spec, i) => {
        if (got[i]?.regex !== spec.source || got[i]?.flags !== spec.flags) mismatches.push(`${rule.id}#${i}`);
      });
    }
    expect(mismatches).toEqual([]);
  });
});

describe('Splunk', () => {
  it('gives every regex a single leading (?i) and drops m, s and x', () => {
    const any = ruleToSPL(ruleWith(VALUES, 'any'));
    for (const v of ['(?i)alpha', '(?i)bravo', '(?i)^charlie', '(?i)delta.echo', '(?i)fox trot']) {
      expect(any).toContain(`match(user_input, "${v}")`);
    }
    expect(any).not.toMatch(/\(\?(?:im|si|x)\)/);
    expect(ruleToSPL(ruleWith(VALUES, 'all'))).toContain('| regex user_input="(?i)^charlie"');
  });

  it('escapes the (?i) pattern for a quoted SPL string, also next to other operators', () => {
    // The condition is a"b\d; SPL needs both the quote and the backslash escaped.
    const value = '(?im)a"b\\d';
    const expected = 'match(user_input, "(?i)a\\"b\\\\d")';
    expect(ruleToSPL(ruleWith([value]))).toContain(expected);
    const mixed = {
      ...ruleWith([]),
      detection: {
        condition: 'any',
        conditions: [
          { field: 'user_input', operator: 'regex', value },
          { field: 'user_input', operator: 'contains', value: 'zulu' },
        ],
      },
    } as unknown as ATRRule;
    const spl = ruleToSPL(mixed);
    expect(spl).toContain(expected);
    expect(spl).toContain('like(user_input, "%zulu%")');
  });
});

describe('Elastic', () => {
  it('writes no flag group into a regexp value and keeps case_insensitive on', () => {
    const query = JSON.stringify(ruleToElastic(ruleWith(VALUES)));
    expect(query).not.toMatch(/"value":"\(\?/);
    expect(query).toContain('"value":"^charlie"');
    expect(query).not.toContain('"case_insensitive":false');
  });
});

describe('Sage', () => {
  it('exports every condition case-insensitive, dropping m, s and x without a warning', () => {
    const { rules, warnings } = atrToSage(ruleWith(VALUES));
    expect(rules.length).toBeGreaterThan(0);
    for (const rule of rules) {
      expect(rule.case_insensitive).toBe(true);
      expect(rule.pattern).not.toMatch(/\(\?[imsx]+\)/);
    }
    expect(warnings.filter((w) => w.kind === 'regex_compat_issue')).toEqual([]);
  });

  it('skips a condition that depends on the u flag, with a warning', () => {
    // An astral character in a class, before a quantifier, or with a case
    // mapping (U+10400 lower-cases to U+10428) means something else without u.
    for (const value of [ASTRAL_CLASS, `${ch(0x1f513)}+`, `${ch(0x10400)}x`]) {
      const { rules, warnings } = atrToSage(ruleWith(['(?i)alpha', value]));
      expect(rules.map((r) => r.pattern).join('\n')).not.toContain(value);
      expect(warnings.some((w) => /depends on the u flag/.test(w.detail))).toBe(true);
    }
  });

  it('exports an astral character used as a plain literal without u', () => {
    // The shape of ATR-2026-00346's output markers. Without u the character is
    // two code units, and a plain literal still matches the same text.
    const literal = `\\[${ch(0x1f513)}JAILBREAK\\]`;
    const { rules, warnings } = atrToSage(ruleWith([literal]));
    expect(warnings.filter((w) => w.kind === 'regex_compat_issue')).toEqual([]);
    expect(rules).toHaveLength(1);
    expect(rules[0]!.pattern).toContain(literal);
    expect(new RegExp(rules[0]!.pattern, 'i').test(`say [${ch(0x1f513)}jailbreak] now`)).toBe(true);
  });

  it('exports every corpus rule case-insensitive', () => {
    const { rules } = atrToSageBatch(loadRulesFromDirectory(RULES_DIR));
    expect(rules.length).toBeGreaterThan(100);
    expect(rules.filter((r) => r.case_insensitive !== true).map((r) => r.id)).toEqual([]);
  });

  it('imports a Sage rule with (?i) and warns when it was case-sensitive', () => {
    const [sage] = atrToSage(ruleWith(['(?i)alpha'])).rules;
    const sensitive = sageToAtr({ ...sage!, pattern: 'alpha', case_insensitive: false });
    const values = (sensitive.rule.detection.conditions as Array<{ value: string }>).map((c) => c.value);
    expect(values.every((v) => v === '(?i)alpha')).toBe(true);
    expect(sensitive.warnings.some((w) => w.kind === 'case_sensitivity_lost')).toBe(true);
    const insensitive = sageToAtr({ ...sage!, pattern: 'alpha', case_insensitive: true });
    expect(insensitive.warnings.some((w) => w.kind === 'case_sensitivity_lost')).toBe(false);
  });
});
