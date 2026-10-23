/**
 * scripts/vendor-suites/fetch-vendor-suites.py --check also verifies the
 * committed LICENSES/ copies: each must be byte-identical to the vendor's
 * license file at the pinned commits, and the manifest's sha256 must match.
 * Driven in a Python subprocess with the module's paths pointed at a temp dir.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const REPO = resolve(import.meta.dirname, '..');
const SCRIPT = resolve(REPO, 'scripts', 'vendor-suites', 'fetch-vendor-suites.py');
const python = spawnSync('python3', ['--version'], { encoding: 'utf-8' }).status === 0;

function problems(setup: string): string[] {
  const driver = `
import hashlib, importlib.util, json, sys, tempfile
from pathlib import Path
spec = importlib.util.spec_from_file_location("fvs", ${JSON.stringify(SCRIPT)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root = Path(tempfile.mkdtemp())
m.REPO_ROOT = root
m.LICENSES_DIR = root / "LICENSES"
m.LICENSES_DIR.mkdir()
raw = b"MIT License\\nCopyright (c) Vendor\\n"
copies = {"acme.LICENSE": raw}
entry = {"vendor": "acme", "commit": "c" * 40, "license_file": "LICENSE", "license_file_sha256": hashlib.sha256(raw).hexdigest(), "copy": "LICENSES/acme.LICENSE"}
manifest = {"licenses": [entry]}
committed = {"licenses": [dict(entry)]}
${setup}
print(json.dumps(m.license_problems(manifest, copies, committed)))
`;
  const r = spawnSync('python3', ['-c', driver], { encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return JSON.parse(r.stdout) as string[];
}

describe.skipIf(!python)('vendor-suite license copies', () => {
  it('passes when the copy is the upstream file and the manifest agrees', () => {
    expect(problems('(m.LICENSES_DIR / "acme.LICENSE").write_bytes(raw)')).toEqual([]);
  });

  it('fails on a missing copy, an edited copy, a stray file or a manifest that disagrees', () => {
    expect(problems('')).toEqual(['LICENSES/acme.LICENSE missing']);
    expect(problems('(m.LICENSES_DIR / "acme.LICENSE").write_bytes(raw + b"edited")').join('\n')).toMatch(/not the upstream file/);
    expect(problems('(m.LICENSES_DIR / "acme.LICENSE").write_bytes(raw); (m.LICENSES_DIR / "other.LICENSE").write_bytes(b"x")')).toEqual([
      'LICENSES/other.LICENSE is not a vendor license this corpus uses',
    ]);
    expect(problems('(m.LICENSES_DIR / "acme.LICENSE").write_bytes(raw); committed["licenses"][0]["license_file_sha256"] = "0"')).toEqual([
      'manifest.json licenses[] differs from upstream (commit, file or sha256)',
    ]);
  });

  it('the committed copies match the sha256 the committed manifest records', () => {
    const manifest = JSON.parse(readFileSync(resolve(REPO, 'data/test-corpora/vendor-guardrail-suites/manifest.json'), 'utf-8')) as {
      licenses: { copy: string; license_file_sha256: string }[];
    };
    expect(manifest.licenses.length).toBeGreaterThan(0);
    for (const l of manifest.licenses) {
      expect(createHash('sha256').update(readFileSync(resolve(REPO, l.copy))).digest('hex')).toBe(l.license_file_sha256);
    }
  });

  it('carries NeMo Guardrails\' full Apache-2.0 text beside its notice, at the sha256 sources.json pins', () => {
    const sources = JSON.parse(readFileSync(resolve(REPO, 'data/test-corpora/vendor-guardrail-suites/sources.json'), 'utf-8')) as {
      vendors: { vendor: string; license_file: string; license_sha256?: string; extra_license_files?: { path: string; sha256: string }[] }[];
    };
    const nemo = sources.vendors.find((v) => v.vendor === 'nemo-guardrails')!;
    const full = nemo.extra_license_files?.find((f) => f.path === 'LICENSE-Apache-2.0.txt');
    expect(full?.sha256).toMatch(/^[0-9a-f]{64}$/);
    const copy = readFileSync(resolve(REPO, 'data/test-corpora/vendor-guardrail-suites/LICENSES/nemo-guardrails.LICENSE-Apache-2.0.txt'));
    expect(createHash('sha256').update(copy).digest('hex')).toBe(full!.sha256);
    expect(copy.toString('utf-8')).toContain('Apache License');
    for (const v of sources.vendors) {
      const main = readFileSync(resolve(REPO, `data/test-corpora/vendor-guardrail-suites/LICENSES/${v.vendor}.${v.license_file}`));
      expect(createHash('sha256').update(main).digest('hex'), v.vendor).toBe(v.license_sha256);
    }
    const manifest = JSON.parse(readFileSync(resolve(REPO, 'data/test-corpora/vendor-guardrail-suites/manifest.json'), 'utf-8')) as {
      licenses: { vendor: string; license_file: string; license_file_sha256: string }[];
    };
    const recorded = manifest.licenses.filter((l) => l.vendor === 'nemo-guardrails' && l.license_file === 'LICENSE-Apache-2.0.txt');
    expect(recorded).toHaveLength(2);
    for (const l of recorded) expect(l.license_file_sha256).toBe(full!.sha256);
  });

  it('refuses a license file whose sha256 differs from the one sources.json pins', () => {
    const driver = `
import importlib.util
spec = importlib.util.spec_from_file_location("fvs", ${JSON.stringify(SCRIPT)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
v = {"license_file": "LICENSE", "license_sha256": "a" * 64, "extra_license_files": [{"path": "FULL.txt", "sha256": "b" * 64}]}
print([f["path"] for f in m.license_files(v)], [f["sha256"][0] for f in m.license_files(v)])
`;
    const r = spawnSync('python3', ['-c', driver], { encoding: 'utf-8' });
    expect(r.stdout.trim()).toBe("['LICENSE', 'FULL.txt'] ['a', 'b']");
    expect(readFileSync(SCRIPT, 'utf-8')).toMatch(/sha256 \{digest\} != sources\.json/);
  });
});
