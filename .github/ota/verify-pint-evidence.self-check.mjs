import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const helper = join(dirname(fileURLToPath(import.meta.url)), 'verify-pint-evidence.mjs');

function git(repo, ...args) {
  return execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'ota-pint-identity-'));
  const repo = join(root, 'repo');
  mkdirSync(join(repo, 'data/pint-benchmark'), { recursive: true });
  mkdirSync(join(repo, 'data/measurements/pint'), { recursive: true });
  mkdirSync(join(repo, 'src/eval'), { recursive: true });
  mkdirSync(join(repo, 'rules'), { recursive: true });
  writeFileSync(join(repo, 'package-lock.json'), '{}\n');
  writeFileSync(join(repo, 'data/pint-benchmark/pint-corpus.json'), '[]\n');
  writeFileSync(join(repo, 'src/eval/run-pint-benchmark.ts'), 'export {};\n');
  writeFileSync(join(repo, 'ota.yaml'), 'version: 1\n');
  writeFileSync(join(repo, 'rules/test.yaml'), 'id: test\n');
  writeFileSync(join(repo, 'data/pint-benchmark/pint-eval-report.json'),
    '{"report":{"timestamp":"2026-01-01T00:00:00Z"}}\n');
  writeFileSync(join(repo, 'data/measurements/pint/latest.json'),
    '{"measured_at":"2026-01-01T00:00:00Z"}\n');
  git(repo, 'init', '-q', '-b', 'main');
  git(repo, 'add', '-A');
  git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example',
    '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'fixture');

  const otaVersion = join(root, 'ota-version.json');
  const nodeVersion = join(root, 'node-version.txt');
  const npmVersion = join(root, 'npm-version.txt');
  const preflight = join(root, 'preflight.json');
  writeFileSync(otaVersion, '{"version":"v1.6.28"}\n');
  writeFileSync(nodeVersion, 'v20.0.0\n');
  writeFileSync(npmVersion, '10.0.0\n');
  execFileSync(process.execPath, [helper, 'preflight', '--repo', repo,
    '--report', 'data/pint-benchmark/pint-eval-report.json',
    '--started-at', '2026-09-26T00:00:00Z', '--ota-version', otaVersion,
    '--node-version', nodeVersion, '--npm-version', npmVersion,
    '--output', preflight]);
  return { root, repo, otaVersion, nodeVersion, npmVersion, preflight };
}

function verify(f) {
  return spawnSync(process.execPath, [helper, 'verify', '--repo', f.repo,
    '--preflight', f.preflight, '--ended-at', '2026-09-26T00:01:00Z',
    '--ota-exit-code', '0', '--atr-gate-exit-code', '0',
    '--ota-version', f.otaVersion, '--node-version', f.nodeVersion,
    '--npm-version', f.npmVersion, '--output', join(f.root, 'evidence.json')],
  { encoding: 'utf8' });
}

test('a different HEAD cannot inherit preflight checkout evidence', () => {
  const f = fixture();
  try {
    writeFileSync(join(f.repo, 'unrelated.txt'), 'next commit\n');
    git(f.repo, 'add', 'unrelated.txt');
    git(f.repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example',
      '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'next');
    const result = verify(f);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /preflight and execution input identities does not reconcile exactly/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

test('changed lockfile bytes cannot inherit preflight input evidence', () => {
  const f = fixture();
  try {
    writeFileSync(join(f.repo, 'package-lock.json'), '{"changed":true}\n');
    const result = verify(f);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /preflight and execution input identities does not reconcile exactly/);
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});
