/**
 * HackAPrompt corpus provenance and in-sample ablation helpers.
 *
 * The HackAPrompt corpus is gated upstream and gitignored here, so the
 * committed record of WHICH samples were measured is the manifest that
 * scripts/hackaprompt-to-corpus.py writes beside it: the HuggingFace dataset
 * id, the pinned dataset revision, the seed, the selected row indices and the
 * SHA-256 of the corpus file. The runner refuses to measure a corpus whose
 * digest does not match the manifest, so a measurement file can only ever
 * describe the sample set its provenance block names.
 *
 * Several rules were written from this same corpus (their YAML names
 * HackAPrompt as the source). Scoring them on it is in-sample, so the runner
 * also measures the corpus with those rules removed.
 *
 * @module agent-threat-rules/eval/hackaprompt-provenance
 */

import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

export interface HackaPromptManifest {
  readonly dataset_id: string;
  readonly dataset_revision: string;
  readonly split: string;
  readonly parquet_sha256: string;
  readonly rows_total: number;
  readonly selection: string;
  readonly seed: number | null;
  readonly requested: number;
  readonly dropped_short_or_empty: number;
  readonly filter: string;
  readonly samples: number;
  readonly corpus_sha256: string;
  readonly sample_ids_sha256: string;
  readonly row_indices: readonly number[];
}

/** Rules ATR-2026-00452..00456, added by e9efefdd on 2026-05-12, mined from this corpus. */
export const HACKAPROMPT_BATCH_0512_RULE_IDS: readonly string[] = [
  'ATR-2026-00452',
  'ATR-2026-00453',
  'ATR-2026-00454',
  'ATR-2026-00455',
  'ATR-2026-00456',
];

export function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function loadManifest(path: string): HackaPromptManifest {
  if (!existsSync(path)) {
    throw new Error(`HackAPrompt manifest not found: ${path} (run scripts/hackaprompt-to-corpus.py)`);
  }
  const m = JSON.parse(readFileSync(path, 'utf-8')) as HackaPromptManifest;
  for (const key of ['dataset_id', 'dataset_revision', 'parquet_sha256', 'corpus_sha256', 'sample_ids_sha256'] as const) {
    if (typeof m[key] !== 'string' || m[key].length === 0) {
      throw new Error(`HackAPrompt manifest ${path}: missing ${key}`);
    }
  }
  if (!Array.isArray(m.row_indices) || m.row_indices.length !== m.samples) {
    throw new Error(`HackAPrompt manifest ${path}: row_indices length != samples`);
  }
  return m;
}

/** Throws unless the corpus file is byte-identical to the one the manifest describes. */
export function verifyCorpusAgainstManifest(corpusPath: string, manifest: HackaPromptManifest): string {
  const actual = sha256File(corpusPath);
  if (actual !== manifest.corpus_sha256) {
    throw new Error(
      `HackAPrompt corpus ${corpusPath} has sha256 ${actual}, manifest expects ${manifest.corpus_sha256}. ` +
        'Regenerate it with scripts/hackaprompt-to-corpus.py at the pinned revision.'
    );
  }
  return actual;
}

function listYaml(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return listYaml(p);
    return /\.ya?ml$/.test(name) ? [p] : [];
  });
}

function ruleIdOf(path: string): string | null {
  const m = /^id:\s*["']?([A-Z0-9-]+)["']?\s*$/m.exec(readFileSync(path, 'utf-8'));
  return m ? m[1]! : null;
}

/** Rule ids whose YAML text names HackAPrompt anywhere (description, provenance, test cases). */
export function rulesNamingHackaPrompt(rulesDir: string): readonly string[] {
  return listYaml(rulesDir)
    .filter((p) => /hackaprompt/i.test(readFileSync(p, 'utf-8')))
    .map(ruleIdOf)
    .filter((id): id is string => id !== null)
    .sort();
}

/**
 * A temporary copy of `rulesDir` without the given rule ids. Returns the copy's
 * path and the ids actually removed (an id with no file is not silently claimed).
 */
export function rulesDirWithout(
  rulesDir: string,
  excludeIds: readonly string[]
): { readonly dir: string; readonly removed: readonly string[] } {
  const exclude = new Set(excludeIds);
  const removed: string[] = [];
  const dir = join(mkdtempSync(join(tmpdir(), 'atr-hap-ablation-')), 'rules');
  cpSync(rulesDir, dir, {
    recursive: true,
    filter: (src) => {
      if (!/\.ya?ml$/.test(src) || statSync(src).isDirectory()) return true;
      const id = ruleIdOf(src);
      if (id !== null && exclude.has(id)) {
        removed.push(id);
        return false;
      }
      return true;
    },
  });
  const missing = excludeIds.filter((id) => !removed.includes(id));
  if (missing.length > 0) {
    throw new Error(`rulesDirWithout: no rule file for ${missing.join(', ')} under ${rulesDir}`);
  }
  return { dir, removed: [...removed].sort() };
}

/** Repo-relative path, for records that must not carry a machine-local path. */
export function repoRelative(base: string, path: string): string {
  return relative(base, path) || '.';
}
