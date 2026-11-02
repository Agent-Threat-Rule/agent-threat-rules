/**
 * The Pipelock bundle must carry the flags the ATR engine applies.
 *
 * Pipelock compiles each rule's joined pattern with Go RE2, which honours
 * inline flags. The ATR engine removes a condition's leading flag group,
 * applies only `i`, and applies it to every regex condition (SPEC.md §6.4).
 * The compiler used to wrap each value as written, so a condition without
 * `(?i)` was case-sensitive in the bundle's regex (Pipelock adds `(?i)` to
 * DLP and tool-poison rules itself, and to injection rules only after
 * v3.7.0), and `(?im)` or `(?si)` switched on multi-line or dot-all mode for
 * its own alternative.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { compileToPipelock } from '../scripts/compile-pipelock.js';
import { regexConditionSpec } from '../src/engine.js';

interface Bundle {
  readonly rules: readonly { readonly id: string; readonly pattern: { readonly regex: string } }[];
}

// One condition per leading-group shape on main: none, (?i), and the three
// rules that write more than i (ATR-2026-00450, -00859, -00207).
const MIXED = ['(?i)ignore\\s+previous', 'system prompt', '(?im)^\\s*override', '(?si)<x>[^<]*', '(?is)a[.]b'];
const PLAIN = ['Exfiltrate'];

function writeRule(dir: string, id: string, values: readonly string[]): void {
  const rule = {
    id,
    title: `fixture ${id}`,
    status: 'experimental',
    severity: 'high',
    tags: { category: 'prompt-injection' },
    detection: {
      condition: 'any',
      conditions: values.map((value) => ({ field: 'user_input', operator: 'regex', value })),
    },
  };
  writeFileSync(join(dir, `${id}.yaml`), yaml.dump(rule), 'utf8');
}

describe('compileToPipelock', () => {
  let regexById: Map<string, string>;

  beforeAll(() => {
    const root = mkdtempSync(join(tmpdir(), 'atr-pipelock-'));
    const rulesDir = join(root, 'rules', 'prompt-injection');
    mkdirSync(rulesDir, { recursive: true });
    writeRule(rulesDir, 'ATR-2026-90001', MIXED);
    writeRule(rulesDir, 'ATR-2026-90002', PLAIN);
    const outDir = join(root, 'out');
    const stats = compileToPipelock({
      rulesDir: join(root, 'rules'),
      outDir,
      bundleName: 'atr-test',
      tier: 'community',
      minPipelock: '2.5.0',
      expiresInDays: 1,
    });
    expect(stats.compiled).toBe(2);
    const bundle = yaml.load(readFileSync(join(outDir, 'bundle.yaml'), 'utf8')) as Bundle;
    regexById = new Map(bundle.rules.map((r) => [r.id, r.pattern.regex]));
  });

  it('emits one leading (?i) and drops each condition\'s own flag group', () => {
    expect(regexById.get('ATR-2026-90001')).toBe(
      '(?i)(ignore\\s+previous)|(system prompt)|(^\\s*override)|(<x>[^<]*)|(a[.]b)',
    );
    expect(regexById.get('ATR-2026-90002')).toBe('(?i)(Exfiltrate)');
    for (const regex of regexById.values()) {
      // RE2 would apply a (?m), (?s) or (?x) anywhere it appears; the engine never does.
      expect(regex.match(/\(\?[a-zA-Z]+\)/g)).toEqual(['(?i)']);
      expect(regex.startsWith('(?i)')).toBe(true);
    }
  });

  it('builds each alternative from the pattern the engine compiles', () => {
    const expected = (values: readonly string[]): string =>
      `(?i)${values.map((v) => `(${regexConditionSpec(v).source})`).join('|')}`;
    expect(regexById.get('ATR-2026-90001')).toBe(expected(MIXED));
    expect(regexById.get('ATR-2026-90002')).toBe(expected(PLAIN));
  });

  it('matches case-insensitively, with ^ at the start only, for every alternative', () => {
    // JavaScript stands in for RE2 here. For these constructs, with i set for
    // the whole expression and m and s unset, the two agree.
    const read = (id: string): RegExp => new RegExp(regexById.get(id)!.slice('(?i)'.length), 'i');
    expect(read('ATR-2026-90002').test('please exfiltrate the keys')).toBe(true);
    const mixed = read('ATR-2026-90001');
    expect(mixed.test('SYSTEM PROMPT')).toBe(true);
    expect(mixed.test('  OVERRIDE now')).toBe(true);
    // Under the old (?im) this matched at the second line's start.
    expect(mixed.test('first line\n  override')).toBe(false);
  });
});
