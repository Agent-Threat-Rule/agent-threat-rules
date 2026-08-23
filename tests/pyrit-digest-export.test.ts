/**
 * Tests for the PyRIT rule-digest exporter (`scripts/export-pyrit-digest.py`).
 *
 * The exporter exists because microsoft/PyRIT reverted an ATR scorer that
 * imported `pyatr` — the maintainer did not want PyRIT's release health tied to
 * ours. The replacement ships data instead of code, so the properties worth
 * testing are the ones a consumer cannot check for themselves: that a pattern
 * which will not compile never reaches the artifact, and that the set of things
 * we dropped cannot grow without failing the build.
 *
 * The script is Python and the suite is vitest, so these run the real script as
 * a subprocess against a fixture tree via `--root`. That is deliberate: the
 * promise made upstream was about the script's exit code, and asserting on a
 * reimplementation of it would not test the promise.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SCRIPT = resolve(__dirname, '../scripts/export-pyrit-digest.py');

function fixtureRoot(rules: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'atr-pyrit-digest-'));
  mkdirSync(join(root, 'rules', 'fixtures'), { recursive: true });
  for (const [name, body] of Object.entries(rules)) {
    writeFileSync(join(root, 'rules', 'fixtures', `${name}.yaml`), body);
  }
  return root;
}

function run(root: string, args: string[] = []): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(
      'python3',
      [SCRIPT, '--root', root, '--out', join(root, 'digest.json'), '--baseline', join(root, 'baseline.json'), ...args],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return { status: 0, stdout, stderr: '' };
  } catch (err: any) {
    return { status: err.status ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const good = `
title: Good rule
id: ATR-TEST-0001
severity: high
maturity: stable
status: stable
detection:
  condition: any
  conditions:
    - field: content
      operator: regex
      value: "(?i)ignore all previous instructions"
`;

describe('export-pyrit-digest', () => {
  it('includes a compilable any-condition rule and lifts its inline flag', () => {
    const root = fixtureRoot({ good });
    expect(run(root, ['--update-baseline']).status).toBe(0);
    const digest = JSON.parse(readFileSync(join(root, 'digest.json'), 'utf8'));
    expect(digest.rules['ATR-TEST-0001'].ignore_case).toBe(true);
    // `(?i)` is only legal at the start of a Python pattern, so it is declared
    // once on the rule rather than left inline where a consumer that joins
    // patterns would produce an uncompilable expression.
    expect(digest.rules['ATR-TEST-0001'].patterns[0]).not.toContain('(?i)');
    expect(digest.engine).toBe('python-re');
  });

  it('drops a pattern that will not compile under Python re, and says why', () => {
    // Variable-width lookbehind: legal in PCRE and in the ATR spec's
    // ECMAScript dialect, rejected by Python. Real instances exist in the
    // corpus, which is how this class of failure was found.
    const root = fixtureRoot({
      good,
      bad: good.replace('ATR-TEST-0001', 'ATR-TEST-0002').replace(
        '"(?i)ignore all previous instructions"',
        '"(?<!.{1,5})nope"',
      ),
    });
    expect(run(root, ['--update-baseline']).status).toBe(0);
    const digest = JSON.parse(readFileSync(join(root, 'digest.json'), 'utf8'));
    expect(digest.rules['ATR-TEST-0002']).toBeUndefined();
    expect(digest.rules['ATR-TEST-0001']).toBeDefined();
    const reasons = digest.exclusions.filter((e: any) => e.rule === 'ATR-TEST-0002').map((e: any) => e.reason);
    expect(reasons).toContain('pattern-uncompilable');
  });

  it('drops an all-condition rule rather than approximating it', () => {
    // RegexScorer fires when ANY named pattern matches. A rule that requires
    // every condition would be reported on a single match, which it never
    // claimed, so it is excluded instead of quietly widened.
    const root = fixtureRoot({
      good,
      all: good.replace('ATR-TEST-0001', 'ATR-TEST-0003').replace('condition: any', 'condition: all'),
    });
    expect(run(root, ['--update-baseline']).status).toBe(0);
    const digest = JSON.parse(readFileSync(join(root, 'digest.json'), 'utf8'));
    expect(digest.rules['ATR-TEST-0003']).toBeUndefined();
    expect(digest.exclusions.some((e: any) => e.rule === 'ATR-TEST-0003' && e.reason === 'condition-not-any')).toBe(true);
  });

  it('drops a rule whose only field a text scorer cannot see', () => {
    const root = fixtureRoot({
      good,
      trace: good.replace('ATR-TEST-0001', 'ATR-TEST-0004').replace('field: content', 'field: trace.forbid_violation'),
    });
    expect(run(root, ['--update-baseline']).status).toBe(0);
    const digest = JSON.parse(readFileSync(join(root, 'digest.json'), 'utf8'));
    expect(digest.rules['ATR-TEST-0004']).toBeUndefined();
    expect(digest.exclusions.some((e: any) => e.rule === 'ATR-TEST-0004' && e.reason === 'no-usable-pattern')).toBe(true);
  });

  it('fails the build when the exclusion set grows', () => {
    // This is the property promised upstream. agent-governance-toolkit's weekly
    // ATR sync skips invalid patterns with a warning, so nobody downstream can
    // tell how many rules a release lost. Here a new exclusion is an error.
    const root = fixtureRoot({ good });
    expect(run(root, ['--update-baseline']).status).toBe(0);
    expect(run(root).status).toBe(0);

    writeFileSync(
      join(root, 'rules', 'fixtures', 'new-bad.yaml'),
      good.replace('ATR-TEST-0001', 'ATR-TEST-0005').replace('"(?i)ignore all previous instructions"', '"(?<!.{1,5})nope"'),
    );
    const drifted = run(root);
    expect(drifted.status).toBe(1);
    expect(drifted.stderr).toContain('EXCLUSION SET CHANGED');
    expect(drifted.stderr).toContain('ATR-TEST-0005');
  });

  it('refuses to run without a baseline rather than defaulting to permissive', () => {
    const root = fixtureRoot({ good });
    const first = run(root);
    expect(first.status).toBe(1);
    expect(first.stderr).toContain('no baseline');
    expect(existsSync(join(root, 'baseline.json'))).toBe(false);
  });

  it('--strict rejects any exclusion at all', () => {
    const root = fixtureRoot({
      good,
      bad: good.replace('ATR-TEST-0001', 'ATR-TEST-0006').replace('"(?i)ignore all previous instructions"', '"(?<!.{1,5})nope"'),
    });
    expect(run(root, ['--update-baseline']).status).toBe(0);
    const strict = run(root, ['--strict']);
    expect(strict.status).toBe(1);
    expect(strict.stderr).toContain('STRICT');
  });
});
