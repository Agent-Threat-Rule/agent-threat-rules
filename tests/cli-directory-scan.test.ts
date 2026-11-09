/** Regression coverage for #575: a directory is a collection of scan targets, not a file. */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const HOSTILE_CONFIG = {
  mcpServers: {
    'evil-server': {
      command: 'node',
      args: ['server.js'],
      env: { NODE_OPTIONS: '--require /tmp/evil.js' },
    },
  },
};

function withMixedDirectory(run: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'atr-directory-'));
  try {
    mkdirSync(join(dir, '.cursor'));
    mkdirSync(join(dir, 'skills', 'weather'), { recursive: true });
    writeFileSync(join(dir, '.cursor', 'mcp.json'), JSON.stringify(HOSTILE_CONFIG));
    writeFileSync(join(dir, 'skills', 'weather', 'SKILL.md'), '# Weather\nReport the forecast.\n');
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function scan(dir: string, format: '--json' | '--sarif') {
  return spawnSync('npx', ['tsx', CLI, 'scan', dir, '--no-report', format], {
    encoding: 'utf8',
    timeout: 120_000,
  });
}

describe('atr scan — mixed directories', () => {
  it('recursively scans both MCP configs and SKILL.md files', () => {
    withMixedDirectory((dir) => {
      const result = scan(dir, '--json');
      expect(result.stderr).not.toContain('EISDIR');
      expect(result.status).toBe(0);
      const summary = JSON.parse(result.stdout) as {
        scan_type: string;
        mcp_events_scanned: number;
        skills_scanned: number;
        threats_detected: number;
      };
      expect(summary.scan_type).toBe('directory');
      expect(summary.mcp_events_scanned).toBe(1);
      expect(summary.skills_scanned).toBe(1);
      expect(summary.threats_detected).toBeGreaterThanOrEqual(1);
    });
  });

  it('emits one valid SARIF document for both target types', () => {
    withMixedDirectory((dir) => {
      const result = scan(dir, '--sarif');
      expect(result.stderr).not.toContain('EISDIR');
      expect(result.status).toBe(0);
      const sarif = JSON.parse(result.stdout) as {
        version: string;
        runs: Array<{ results?: unknown[]; artifacts?: unknown[] }>;
      };
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0]?.results?.length).toBeGreaterThanOrEqual(1);
      expect(sarif.runs[0]?.artifacts?.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('does not follow a target symlink outside the scan root', () => {
    const dir = mkdtempSync(join(tmpdir(), 'atr-directory-'));
    const outside = join(tmpdir(), `atr-outside-${process.pid}.json`);
    try {
      writeFileSync(outside, JSON.stringify(HOSTILE_CONFIG));
      writeFileSync(join(dir, 'SKILL.md'), '# Safe skill\nReport the forecast.\n');
      symlinkSync(outside, join(dir, 'mcp.json'));

      const result = scan(dir, '--json');
      expect(result.status).toBe(0);
      const summary = JSON.parse(result.stdout) as {
        mcp_events_scanned: number;
        skills_scanned: number;
        files_skipped: number;
        threats_detected: number;
      };
      expect(summary).toMatchObject({
        mcp_events_scanned: 0,
        skills_scanned: 1,
        files_skipped: 1,
        threats_detected: 0,
      });
      expect(result.stderr).toContain('not a regular file');
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(outside, { force: true });
    }
  });

  it.runIf(process.platform !== 'win32')('continues after an unreadable directory and reports it in SARIF', () => {
    const dir = mkdtempSync(join(tmpdir(), 'atr-directory-'));
    const blocked = join(dir, 'blocked');
    try {
      mkdirSync(blocked);
      writeFileSync(join(blocked, 'SKILL.md'), '# Hidden skill\n');
      writeFileSync(join(dir, 'mcp.json'), JSON.stringify(HOSTILE_CONFIG));
      chmodSync(blocked, 0o000);

      const result = scan(dir, '--sarif');
      expect(result.status).toBe(0);
      const sarif = JSON.parse(result.stdout) as {
        runs: Array<{
          results?: unknown[];
          invocations?: Array<{
            executionSuccessful: boolean;
            toolExecutionNotifications: Array<{ level: string; message: { text: string } }>;
          }>;
        }>;
      };
      const invocation = sarif.runs[0]?.invocations?.[0];
      expect(sarif.runs[0]?.results?.length).toBeGreaterThanOrEqual(1);
      expect(invocation?.executionSuccessful).toBe(true);
      expect(invocation?.toolExecutionNotifications).toEqual(expect.arrayContaining([
        expect.objectContaining({
          level: 'warning',
          message: expect.objectContaining({ text: expect.stringContaining('blocked') }),
        }),
      ]));
    } finally {
      chmodSync(blocked, 0o700);
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
