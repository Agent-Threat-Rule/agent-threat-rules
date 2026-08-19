/**
 * Tests for the Cisco Skill Scanner pack exporter.
 *
 * The exporter's real acceptance test is
 * `scripts/cisco-pack/verify-reproduction.ts`, which regenerates the pack
 * vendored in cisco-ai-defense/skill-scanner and compares 1.36 MB of it byte
 * for byte. That needs a checkout of the downstream repo, so it is not run
 * here. What is run here is the part that made byte-for-byte possible: the
 * scalar-style rules, the field transform, and the exclusion rule — each with
 * the concrete case that caught it.
 */

import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { describe, expect, it } from 'vitest';
import { loadRules, extractPatterns, type AtrRule } from '../scripts/cisco-pack/load-rules.js';
import { buildSignatureFiles, toSignature, toSignatureId, DEFAULT_REPO_URL } from '../scripts/cisco-pack/transform.js';
import { chooseScalarStyle, emitYaml } from '../scripts/cisco-pack/yaml-emit.js';

const OPTIONS = { ref: 'main', repoUrl: DEFAULT_REPO_URL };

function rule(overrides: Partial<AtrRule> & { id: string }): AtrRule {
  return {
    severity: 'high',
    description: 'A rule.',
    detection: { conditions: [{ field: 'user_input', operator: 'regex', value: 'abc' }] },
    ...overrides,
  } as AtrRule;
}

describe('chooseScalarStyle', () => {
  it('writes a short safe scalar plain', () => {
    expect(chooseScalarStyle('(?i)\\bfoo\\b')).toBe('plain');
  });

  it('folds anything longer than 70 characters', () => {
    expect(chooseScalarStyle('a'.repeat(70))).toBe('plain');
    expect(chooseScalarStyle('a'.repeat(71))).toBe('folded');
  });

  it('quotes a scalar that would resolve as a number', () => {
    // A real pattern in ATR-2026-00538: unquoted this parses as a hex integer.
    expect(chooseScalarStyle('0x5d5acA289F2A9E481fa2aEaD3FA465880Df84354')).toBe('single');
  });

  it('treats a leading "--" as safe but "---" as a document marker', () => {
    expect(chooseScalarStyle('--\\s*(?:CORE\\s+INSTRUCTION)')).toBe('plain');
    expect(chooseScalarStyle('-----BEGIN (?:RSA )?PRIVATE KEY-----')).toBe('single');
  });

  it('double-quotes a value with trailing whitespace', () => {
    // Truncating a description to 300 code points can land on a space.
    expect(chooseScalarStyle(`${'a'.repeat(80)} `)).toBe('double');
  });

  it('double-quotes a value carrying a byte order mark', () => {
    expect(chooseScalarStyle(`[​⁠﻿]{3,}${'x'.repeat(80)}`)).toBe('double');
  });

  it('folds rather than quotes a value carrying a line feed', () => {
    expect(chooseScalarStyle('`(?:ls|touch)[^`\n]{0,100}`')).toBe('folded');
  });
});

describe('emitYaml', () => {
  it('round-trips every scalar style through a YAML parser', () => {
    const values = [
      '',
      'plain',
      '0x5d5acA289F2A9E481fa2aEaD3FA465880Df84354',
      '-----BEGIN (?:RSA )?PRIVATE KEY-----',
      `${'a'.repeat(80)} `,
      `[​⁠﻿]{3,}${'x'.repeat(80)}`,
      '`(?:ls|touch)[^`\n]{0,100}`',
      'a'.repeat(300),
      "it's got 'quotes' and: colons",
    ];
    const text = emitYaml({ signatures: [{ patterns: values }] });
    const parsed = yaml.load(text) as { signatures: { patterns: string[] }[] };
    expect(parsed.signatures[0].patterns).toEqual(values);
  });

  it('emits a shared array once as an anchor and then as an alias', () => {
    const shared = ['markdown', 'json'];
    const text = emitYaml(
      { signatures: [{ file_types: shared }, { file_types: shared }] },
      { anchoredKeys: { file_types: 'id001' } },
    );
    expect(text).toContain('file_types: &id001');
    expect(text).toContain('file_types: *id001');
    const parsed = yaml.load(text) as { signatures: { file_types: string[] }[] };
    expect(parsed.signatures[1].file_types).toEqual(shared);
  });
});

describe('toSignature', () => {
  const loaded = {
    category: 'tool-poisoning',
    fileName: 'ATR-2026-00001-example.yaml',
    rule: rule({ id: 'ATR-2026-00001', severity: 'critical' }),
  };

  it('maps ids, category and severity into the pack shape', () => {
    const signature = toSignature(loaded, OPTIONS);
    expect(signature.id).toBe('ATR_2026_00001');
    expect(signature.atr_id).toBe('ATR-2026-00001');
    expect(signature.category).toBe('tool_poisoning');
    expect(signature.severity).toBe('CRITICAL');
    expect(signature.atr_url).toBe(
      `${DEFAULT_REPO_URL}/blob/main/rules/tool-poisoning/ATR-2026-00001-example.yaml`,
    );
  });

  it('takes the category from the directory, not from tags.category', () => {
    // ATR-2026-00072 lives in rules/model-security/ but is tagged model-abuse.
    const signature = toSignature(
      { ...loaded, category: 'model-security', rule: rule({ id: 'ATR-2026-00072' }) },
      OPTIONS,
    );
    expect(signature.category).toBe('model_security');
  });

  it('keeps runs of spaces when flattening a description', () => {
    const signature = toSignature(
      { ...loaded, rule: rule({ id: 'ATR-2026-00002', description: 'One.  Two.\nThree.\n' }) },
      OPTIONS,
    );
    expect(signature.description).toBe('One.  Two. Three.');
  });

  it('truncates a description by code point, not by UTF-16 unit', () => {
    const description = `${'🔓'.repeat(150)}${'a'.repeat(200)}`;
    const signature = toSignature(
      { ...loaded, rule: rule({ id: 'ATR-2026-00003', description }) },
      OPTIONS,
    );
    expect(Array.from(signature.description)).toHaveLength(300);
    expect(signature.description.endsWith('a'.repeat(150))).toBe(true);
  });

  it('keeps a regex repeated across two fields', () => {
    // ATR-2026-00398 carries the same pattern for tool_response and user_input.
    const repeated = rule({
      id: 'ATR-2026-00398',
      detection: {
        conditions: [
          { field: 'tool_response', operator: 'regex', value: 'pickle\\.load' },
          { field: 'user_input', operator: 'regex', value: 'pickle\\.load' },
        ],
      },
    });
    expect(extractPatterns(repeated)).toEqual(['pickle\\.load', 'pickle\\.load']);
  });

  it('drops conditions whose operator is not regex', () => {
    const mixed = rule({
      id: 'ATR-2026-00004',
      detection: {
        conditions: [
          { field: 'user_input', operator: 'regex', value: 'keep' },
          { field: 'user_input', operator: 'equals', value: 'drop' },
        ],
      },
    });
    expect(extractPatterns(mixed)).toEqual(['keep']);
  });
});

describe('loadRules', () => {
  function writeRuleTree(rules: { dir: string; name: string; body: unknown }[]): string {
    const root = mkdtempSync(join(tmpdir(), 'atr-rules-'));
    for (const { dir, name, body } of rules) {
      mkdirSync(join(root, dir), { recursive: true });
      writeFileSync(join(root, dir, name), yaml.dump(body), 'utf8');
    }
    return root;
  }

  it('excludes a behavioral rule and reports why', () => {
    const root = writeRuleTree([
      {
        dir: 'excessive-autonomy',
        name: 'ATR-2026-00553-runaway.yaml',
        body: {
          id: 'ATR-2026-00553',
          severity: 'high',
          description: 'Runaway loop.',
          detection: {
            method: 'behavioral',
            conditions: [{ field: 'behavioral.metric_value', operator: 'regex', value: 'x' }],
          },
        },
      },
      {
        dir: 'excessive-autonomy',
        name: 'ATR-2026-00554-other.yaml',
        body: {
          id: 'ATR-2026-00554',
          severity: 'high',
          description: 'Static rule.',
          detection: { conditions: [{ field: 'user_input', operator: 'regex', value: 'x' }] },
        },
      },
    ]);
    const loaded = loadRules(root);
    expect(loaded.rules.map((r) => r.rule.id)).toEqual(['ATR-2026-00554']);
    expect(loaded.excluded).toEqual([
      { id: 'ATR-2026-00553', reason: 'detection.method: behavioral' },
    ]);
    // The per-category file count still counts the excluded rule's file.
    expect(loaded.filesPerCategory['excessive-autonomy']).toBe(2);
  });

  it('keeps semantic and trace rules, which do carry regex conditions', () => {
    const root = writeRuleTree(
      ['semantic', 'trace'].map((method, index) => ({
        dir: 'prompt-injection',
        name: `ATR-2026-0000${index}-x.yaml`,
        body: {
          id: `ATR-2026-0000${index}`,
          severity: 'high',
          description: 'x',
          detection: { method, conditions: [{ field: 'user_input', operator: 'regex', value: 'x' }] },
        },
      })),
    );
    expect(loadRules(root).rules).toHaveLength(2);
  });

  it('rejects a rule file with no id rather than emitting a nameless signature', () => {
    const root = writeRuleTree([
      { dir: 'prompt-injection', name: 'broken.yaml', body: { severity: 'high' } },
    ]);
    expect(() => loadRules(root)).toThrow(/missing rule id/);
  });
});

describe('buildSignatureFiles', () => {
  it('groups by category and sorts both categories and rules by id', () => {
    const files = buildSignatureFiles(
      [
        { category: 'tool-poisoning', fileName: 'b.yaml', rule: rule({ id: 'ATR-2026-00200' }) },
        { category: 'agent-manipulation', fileName: 'a.yaml', rule: rule({ id: 'ATR-2026-00100' }) },
        { category: 'tool-poisoning', fileName: 'c.yaml', rule: rule({ id: 'ATR-2026-00050' }) },
      ],
      OPTIONS,
    );
    expect(files.map((f) => f.path)).toEqual([
      'signatures/atr_agent_manipulation.yaml',
      'signatures/atr_tool_poisoning.yaml',
    ]);
    expect(files[1].signatures.map((s) => s.atr_id)).toEqual([
      'ATR-2026-00050',
      'ATR-2026-00200',
    ]);
  });
});

describe('toSignatureId', () => {
  it('replaces every dash so the id is a valid identifier', () => {
    expect(toSignatureId('ATR-2026-01610')).toBe('ATR_2026_01610');
  });
});

describe('generated pack.yaml', () => {
  it('is a mapping the downstream PackLoader can read', async () => {
    const { renderPackManifest } = await import('../scripts/cisco-pack/render.js');
    const files = buildSignatureFiles(
      [{ category: 'tool-poisoning', fileName: 'a.yaml', rule: rule({ id: 'ATR-2026-00001' }) }],
      OPTIONS,
    );
    const text = renderPackManifest(files, {
      version: '4.0.0',
      repoUrl: DEFAULT_REPO_URL,
      benchmarkSentence: 'Benchmarks: none.',
      benchmarkReadmeLine: 'none',
    });
    const parsed = yaml.load(text) as Record<string, unknown>;
    // PackLoader reads these three from the top level and calls .items() on
    // `rules`; a sequence there is what makes the currently vendored manifest
    // raise AttributeError.
    expect(parsed.name).toBe('atr');
    expect(parsed.version).toBe('4.0.0');
    expect(typeof parsed.description).toBe('string');
    expect(Array.isArray(parsed.rules)).toBe(false);
    const rules = parsed.rules as Record<string, Record<string, unknown>>;
    expect(rules.ATR_2026_00001.source).toBe('signature');
    expect(rules.ATR_2026_00001.knobs).toEqual({ enabled: true });
  });

  it('still emits the legacy sequence shape when reproducing the vendored pack', async () => {
    const { renderPackManifest } = await import('../scripts/cisco-pack/render.js');
    const files = buildSignatureFiles(
      [{ category: 'tool-poisoning', fileName: 'a.yaml', rule: rule({ id: 'ATR-2026-00001' }) }],
      OPTIONS,
    );
    const text = renderPackManifest(files, {
      version: '3.5.6',
      repoUrl: DEFAULT_REPO_URL,
      benchmarkSentence: 'Benchmarks: none.',
      benchmarkReadmeLine: 'none',
      reproduceVendored: true,
      filesPerCategory: { 'tool-poisoning': 1 },
    });
    const parsed = yaml.load(text) as Record<string, unknown>;
    expect(Array.isArray(parsed.rules)).toBe(true);
    expect((parsed.pack as Record<string, unknown>).id).toBe('atr');
  });
});

describe('generated signature files', () => {
  it('carry maturity, so a consumer can filter to the stable tier', async () => {
    const { renderSignatureFile } = await import('../scripts/cisco-pack/render.js');
    const files = buildSignatureFiles(
      [
        {
          category: 'tool-poisoning',
          fileName: 'a.yaml',
          rule: rule({ id: 'ATR-2026-00001', maturity: 'stable' }),
        },
      ],
      OPTIONS,
    );
    const text = renderSignatureFile(files[0], {
      version: '3.5.12',
      repoUrl: DEFAULT_REPO_URL,
      benchmarkSentence: '',
      benchmarkReadmeLine: '',
    });
    const parsed = yaml.load(text) as { signatures: { maturity?: string }[] };
    expect(parsed.signatures[0].maturity).toBe('stable');
  });

  it('omit maturity when reproducing the pack vendored downstream', async () => {
    const { renderSignatureFile } = await import('../scripts/cisco-pack/render.js');
    const files = buildSignatureFiles(
      [
        {
          category: 'tool-poisoning',
          fileName: 'a.yaml',
          rule: rule({ id: 'ATR-2026-00001', maturity: 'stable' }),
        },
      ],
      { ...OPTIONS, omitMaturity: true },
    );
    const text = renderSignatureFile(files[0], {
      version: '3.5.6',
      repoUrl: DEFAULT_REPO_URL,
      benchmarkSentence: '',
      benchmarkReadmeLine: '',
      reproduceVendored: true,
      filesPerCategory: { 'tool-poisoning': 1 },
    });
    expect(text).not.toContain('maturity:');
    expect(text).toContain('convert-to-skill-scanner.mjs');
  });
});

describe('exporter output is stable', () => {
  it('produces identical bytes on two runs of the same input', () => {
    const root = mkdtempSync(join(tmpdir(), 'atr-stable-'));
    mkdirSync(join(root, 'prompt-injection'), { recursive: true });
    writeFileSync(
      join(root, 'prompt-injection', 'ATR-2026-00001-x.yaml'),
      yaml.dump({
        id: 'ATR-2026-00001',
        severity: 'high',
        description: 'x'.repeat(400),
        detection: { conditions: [{ field: 'user_input', operator: 'regex', value: 'y'.repeat(90) }] },
      }),
      'utf8',
    );
    const once = buildSignatureFiles(loadRules(root).rules, OPTIONS);
    const twice = buildSignatureFiles(loadRules(root).rules, OPTIONS);
    expect(JSON.stringify(once)).toBe(JSON.stringify(twice));
    expect(readFileSync(join(root, 'prompt-injection', 'ATR-2026-00001-x.yaml'), 'utf8').length).toBeGreaterThan(0);
  });
});
