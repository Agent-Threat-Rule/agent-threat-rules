/**
 * PoC-vs-prose grounding routing tests for generate-detection-from-poc.ts
 *
 * Guards the MiroFish failure mode: a detection rule whose patterns were
 * inferred from advisory *description prose* (e.g. "RCE via POST /api/exec")
 * detects the sentence describing the attack, not the attack. Such proposals
 * must NEVER auto-merge.
 *
 * The generator is CLI-only, so these tests drive the real binary and assert
 * the exit-code contract that cve-daily-sync.yml depends on:
 *   exit 0  PoC-grounded  -> promoted to experimental (auto-merge candidate)
 *   exit 3  prose-only    -> draft + needs-human-poc (routed to human review)
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const SCRIPT = resolve(REPO_ROOT, 'scripts/generate-detection-from-poc.ts');
const TSX = resolve(REPO_ROOT, 'node_modules/.bin/tsx');
const FIXTURES = resolve(__dirname, 'fixtures/poc-grounding');

function runGenerator(fixture: string): { status: number | null; rule: any } {
  const tmp = mkdtempSync(join(tmpdir(), 'atr-grounding-'));
  const outPath = join(tmp, 'rule.yaml');
  const res = spawnSync(
    TSX,
    [SCRIPT, resolve(FIXTURES, fixture), '--output', outPath],
    { cwd: REPO_ROOT, encoding: 'utf-8' },
  );
  let rule: any = null;
  try {
    rule = yaml.load(readFileSync(outPath, 'utf-8'));
  } catch {
    rule = null;
  }
  rmSync(tmp, { recursive: true, force: true });
  return { status: res.status, rule };
}

describe('generate-detection-from-poc grounding routing', () => {
  it('PoC-grounded proposal is promoted to experimental and exits 0', () => {
    const { status, rule } = runGenerator('poc-grounded.proposal.yaml');
    expect(status).toBe(0);
    expect(rule).not.toBeNull();
    expect(rule.status).toBe('experimental');
    expect(rule.maturity).toBe('experimental');
    expect(rule._needs_human_poc).toBeUndefined();
    expect(Array.isArray(rule.detection?.conditions)).toBe(true);
    expect(rule.detection.conditions.length).toBeGreaterThan(0);
  });

  it('emits the generalizable attack indicator, not the literal PoC line or benign setup (#123 regression)', () => {
    const { status, rule } = runGenerator('generalizable-not-literal.proposal.yaml');
    expect(status).toBe(0);
    const values: string[] = rule.detection.conditions.map((c: any) => c.value);
    // The cloud-metadata indicator is emitted in its GENERALIZABLE form...
    expect(values).toContain('(?i)169\\.254\\.169\\.254');
    // ...and the literal PoC line, the benign install command, and the local
    // variable name are NOT shipped as detection patterns (the #123 failure
    // mode where "pip install langsmith" became a rule condition).
    const joined = values.join('\n');
    expect(joined).not.toMatch(/pip install/i);
    expect(joined).not.toMatch(/creds_url/);
    expect(joined).not.toMatch(/fetch_url/);
  });

  it('prose-only proposal is blocked from auto-merge and exits 3', () => {
    const { status, rule } = runGenerator('prose-only.proposal.yaml');
    // Exit 3 routes to human review (MiroFish guard), NOT the auto-merge gate.
    expect(status).toBe(3);
    expect(rule).not.toBeNull();
    expect(rule.status).toBe('draft');
    expect(rule.maturity).toBe('needs-human-poc');
    expect(rule._needs_human_poc).toBeDefined();
    expect(typeof rule._needs_human_poc.reason).toBe('string');
    expect(rule._needs_human_poc.reason.length).toBeGreaterThan(0);
  });
});
