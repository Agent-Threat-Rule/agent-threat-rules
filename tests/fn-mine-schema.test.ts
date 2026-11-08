/**
 * Tests for scripts/lib/fn-mine-schema.ts: reading the schema validator's
 * verdict on one authored rule.
 */
import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { schemaProblem } from '../scripts/lib/fn-mine-schema.js';

const OUTPUT = [
  '[PASS] excessive-autonomy/ATR-2026-02667-a.yaml (ATR-2026-02667)',
  '',
  '[FAIL] excessive-autonomy/ATR-2026-02872-b.yaml (ATR-2026-02872)',
  '  ERROR: Invalid response action: block_tool_call',
  '  WARN: test_cases.true_negatives should have at least 2 entries',
  '[PASS] excessive-autonomy/ATR-2026-02874-c.yaml (ATR-2026-02874)',
].join('\n');

describe('schemaProblem', () => {
  it("returns the file's ERROR lines, not its warnings", () => {
    expect(schemaProblem('rules/excessive-autonomy/ATR-2026-02872-b.yaml', OUTPUT)).toBe(
      'npm run validate rejects excessive-autonomy/ATR-2026-02872-b.yaml:\nERROR: Invalid response action: block_tool_call',
    );
  });

  it('passes a file the validator passed, whatever else failed', () => {
    expect(schemaProblem('rules/excessive-autonomy/ATR-2026-02874-c.yaml', OUTPUT)).toBeNull();
    expect(schemaProblem('rules/excessive-autonomy/ATR-2026-02667-a.yaml', OUTPUT)).toBeNull();
  });

  // Against the real validator, run on a scratch tree (its own copy beside one
  // rule) so the probe never appears under this checkout's rules/ while other
  // test files count them.
  it('reads the real validator refusing an unknown response action', () => {
    const repo = resolve(__dirname, '..');
    const root = mkdtempSync(join(tmpdir(), 'fn-mine-schema-'));
    try {
      mkdirSync(join(root, 'tests'));
      copyFileSync(join(repo, 'tests', 'validate-rules.ts'), join(root, 'tests', 'validate-rules.ts'));
      // The package's "type": "module", or tsx runs the copy as CommonJS and import.meta.dirname is undefined.
      copyFileSync(join(repo, 'package.json'), join(root, 'package.json'));
      for (const d of ['src', 'scripts', 'node_modules', 'data']) symlinkSync(join(repo, d), join(root, d));
      mkdirSync(join(root, 'rules', 'excessive-autonomy'), { recursive: true });
      writeFileSync(
        join(root, 'rules', 'excessive-autonomy', 'ATR-2099-99999-schema-probe.yaml'),
        [
          'title: Schema probe',
          'id: ATR-2099-99999',
          'status: experimental',
          'description: probe',
          'author: test',
          'date: 2026/11/08',
          'severity: medium',
          'tags:',
          '  category: excessive-autonomy',
          'agent_source:',
          '  type: llm_io',
          'detection:',
          '  conditions:',
          '    - field: content',
          '      operator: regex',
          '      value: "zzqx"',
          '  condition: any',
          'response:',
          '  actions: [block_tool_call]',
          '',
        ].join('\n'),
      );
      let out = '';
      try {
        out = execSync('npx tsx tests/validate-rules.ts', { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (e) {
        out = String((e as { stdout?: unknown }).stdout ?? '');
      }
      expect(schemaProblem('rules/excessive-autonomy/ATR-2099-99999-schema-probe.yaml', out)).toMatch(
        /Invalid response action: block_tool_call/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);
});
