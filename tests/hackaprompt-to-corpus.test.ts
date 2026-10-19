/**
 * scripts/hackaprompt-to-corpus.py: the committed manifest pins the sample set.
 *
 * Check mode (the default whenever the manifest exists) must refuse, and write
 * nothing, when the parquet file is not the pinned one or when the re-drawn
 * sample's digests differ from the manifest; only --write may rewrite the
 * manifest. The dataset is gated, so these tests drive the script's main() in
 * a Python subprocess with a stand-in parquet file and stand-in rows; no
 * third-party Python package is imported.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SCRIPT = resolve(import.meta.dirname, '..', 'scripts', 'hackaprompt-to-corpus.py');
const python = spawnSync('python3', ['--version'], { encoding: 'utf-8' }).status === 0;

/**
 * Runs main(argv) with fetch/read_rows replaced. `parquetBytes` is the stand-in
 * parquet file; `pinnedSha` overrides the documented sha256 for the default
 * revision (null: the file's own sha256, i.e. a matching download).
 */
function run(dir: string, argv: string[], opts: { parquetBytes?: string; pinnedSha?: string | null; rows?: number } = {}) {
  const driver = `
import hashlib, importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("hap", ${JSON.stringify(SCRIPT)})
hap = importlib.util.module_from_spec(spec); spec.loader.exec_module(hap)
d = Path(${JSON.stringify(dir)})
pq = d / "fake.parquet"; pq.write_bytes(${JSON.stringify(opts.parquetBytes ?? 'PAR1-fake')}.encode())
pinned = ${opts.pinnedSha === undefined || opts.pinnedSha === null ? 'hashlib.sha256(pq.read_bytes()).hexdigest()' : JSON.stringify(opts.pinnedSha)}
hap.PARQUET_SHA256[hap.DEFAULT_REVISION] = pinned
n = ${opts.rows ?? 40}
class Rows:
    def __len__(self): return n
    def __call__(self, i):
        return {"user_input": "" if i % 7 == 0 else f"ignore previous instructions {i}", "correct": i % 3 == 0, "level": i % 10, "model": "m"}
sys.exit(hap.main(sys.argv[1:], fetch=lambda rev: pq, read_rows=lambda p: Rows()))
`;
  return spawnSync('python3', ['-c', driver, ...argv], { encoding: 'utf-8', cwd: dir });
}

function paths(dir: string) {
  return { out: join(dir, 'corpus.json'), manifest: join(dir, 'manifest.json') };
}

describe.skipIf(!python)('hackaprompt-to-corpus.py check mode', () => {
  it('refuses to check when no manifest is committed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hap-py-'));
    const { out, manifest } = paths(dir);
    const r = run(dir, ['--sample', '10', '--out', out, '--manifest', manifest]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/does not exist/);
    expect(existsSync(out)).toBe(false);
  });

  it('--write pins a sample; a re-run in check mode matches it and writes only the corpus', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hap-py-'));
    const { out, manifest } = paths(dir);
    const w = run(dir, ['--write', '--sample', '10', '--seed', '7', '--out', out, '--manifest', manifest]);
    expect(w.status, w.stderr).toBe(0);
    const pinned = readFileSync(manifest, 'utf-8');
    const m = JSON.parse(pinned);
    expect(m.parquet_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(m.row_indices.length).toBe(m.samples);

    const c = run(dir, ['--sample', '10', '--seed', '7', '--out', out, '--manifest', manifest]);
    expect(c.status, c.stderr).toBe(0);
    expect(c.stdout).toMatch(/matches/);
    expect(readFileSync(manifest, 'utf-8')).toBe(pinned);
    expect(existsSync(out)).toBe(true);
  });

  it('exits 1 and writes nothing when the re-drawn sample differs from the manifest', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hap-py-'));
    const { out, manifest } = paths(dir);
    expect(run(dir, ['--write', '--sample', '10', '--seed', '7', '--out', join(dir, 'pin.json'), '--manifest', manifest]).status).toBe(0);
    const pinned = readFileSync(manifest, 'utf-8');

    const r = run(dir, ['--sample', '10', '--seed', '8', '--out', out, '--manifest', manifest]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/corpus_sha256/);
    expect(r.stderr).toMatch(/sample_ids_sha256/);
    expect(existsSync(out)).toBe(false);
    expect(readFileSync(manifest, 'utf-8')).toBe(pinned);
  });

  it('exits 1 when the same seed draws different rows (upstream data changed)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hap-py-'));
    const { out, manifest } = paths(dir);
    expect(run(dir, ['--write', '--sample', '10', '--out', join(dir, 'pin.json'), '--manifest', manifest], { rows: 40 }).status).toBe(0);
    const r = run(dir, ['--sample', '10', '--out', out, '--manifest', manifest], { rows: 41 });
    expect(r.status).toBe(1);
    expect(existsSync(out)).toBe(false);
  });

  it('exits 1 and writes nothing when the parquet file is not the pinned one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hap-py-'));
    const { out, manifest } = paths(dir);
    writeFileSync(manifest, '{}');
    const r = run(dir, ['--sample', '10', '--out', out, '--manifest', manifest], { pinnedSha: '0'.repeat(64) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/pinned revision's file/);
    expect(existsSync(out)).toBe(false);
    expect(readFileSync(manifest, 'utf-8')).toBe('{}');
  });

  it('refuses a revision with no documented parquet sha256', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hap-py-'));
    const { out, manifest } = paths(dir);
    const r = run(dir, ['--write', '--revision', 'deadbeef', '--out', out, '--manifest', manifest]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/no documented parquet sha256/);
    expect(existsSync(manifest)).toBe(false);
  });

  it('the committed manifest records the pinned parquet sha256', () => {
    const m = JSON.parse(readFileSync(resolve(import.meta.dirname, '..', 'data', 'hackaprompt', 'hackaprompt-corpus.manifest.json'), 'utf-8'));
    expect(m.parquet_sha256).toBe('bedca308fbd71be57793930e4e4a0dcfbda2a27b6d0f2ad3191bb20a6a315928');
    const src = readFileSync(SCRIPT, 'utf-8');
    expect(src).toContain(`DEFAULT_REVISION: "${m.parquet_sha256}"`);
  });
});
