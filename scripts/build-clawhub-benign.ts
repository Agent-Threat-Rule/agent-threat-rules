/**
 * Build the ClawHub registry into a reproducible benign corpus file.
 *
 * The registry JSON is 12MB of crawl output. This turns it into a corpus with a
 * fixed sample order, a stable id per sample, a recorded SHA-256 of the source
 * so a later run can prove it read the same bytes, and — most importantly — a
 * manifest that states in the file itself what the text actually is, so nobody
 * downstream can quote a rate from it without meeting the caveat.
 *
 * It writes, it does not scan. Scanning is scripts/measure-clawhub-fp.ts.
 *
 * Run: npx tsx scripts/build-clawhub-benign.ts
 * Out: data/measurements/clawhub-benign/{corpus.jsonl,manifest.json}
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  readRegistry,
  byDownloadsDesc,
  DOWNLOAD_TIERS,
  type ClawhubSample,
} from './lib/clawhub-corpus.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = join(REPO_ROOT, 'data/clawhub-scan/clawhub-registry.json');
const OUT_DIR = join(REPO_ROOT, 'data/measurements/clawhub-benign');

interface LengthStats {
  readonly min: number;
  readonly p50: number;
  readonly p90: number;
  readonly max: number;
  readonly mean: number;
}

function lengthStats(values: readonly number[]): LengthStats {
  const sorted = [...values].sort((a, b) => a - b);
  const at = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor((sorted.length * p) / 100))];
  const sum = sorted.reduce((a, b) => a + b, 0);
  return Object.freeze({
    min: sorted[0],
    p50: at(50),
    p90: at(90),
    max: sorted[sorted.length - 1],
    mean: Number((sum / sorted.length).toFixed(1)),
  });
}

function tierSlices(ranked: readonly ClawhubSample[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const n of DOWNLOAD_TIERS) {
    const slice = ranked.slice(0, n);
    out[`top${n}`] = slice.length > 0 ? slice[slice.length - 1].downloads : 0;
  }
  return out;
}

function main(): void {
  const { samples, sourceSha256 } = readRegistry(SOURCE);
  // Corpus order is download-rank order so a --limit run is always the highest
  // stakes slice, never an arbitrary prefix of the crawl.
  const ranked = byDownloadsDesc(samples);

  mkdirSync(OUT_DIR, { recursive: true });
  const lines = ranked.map((s) => JSON.stringify(s)).join('\n') + '\n';
  writeFileSync(join(OUT_DIR, 'corpus.jsonl'), lines, 'utf8');

  const truncated = ranked.filter((s) => s.truncated).length;
  const manifest = {
    corpus: 'clawhub-benign',
    built: new Date().toISOString(),
    source: 'data/clawhub-scan/clawhub-registry.json',
    source_sha256: sourceSha256,
    corpus_sha256: createHash('sha256').update(lines).digest('hex'),
    samples: ranked.length,
    order: 'downloads desc, id asc',
    downloads_total: ranked.reduce((a, s) => a + s.downloads, 0),
    tier_download_floor: tierSlices(ranked),
    summary_length: lengthStats(ranked.map((s) => s.summary.length)),
    summary_truncated: truncated,
    summary_truncated_pct: Number(((100 * truncated) / ranked.length).toFixed(2)),
    what_the_text_is:
      'The registry description field. NOT SKILL.md content — the crawl stored none. ' +
      'Median 159 chars; 42.9% end in a literal "..." because the registry truncates at 160. ' +
      'A clean result here is clean on registry listing text, not on real skill bodies.',
    not_a_curated_benign_set:
      'This is the registry in full, including whatever malware was published to it. ' +
      'Flagged samples must be triaged by hand before any of them is called a false positive.',
  };
  writeFileSync(join(OUT_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  console.log(
    `built ${ranked.length} samples -> ${OUT_DIR}/corpus.jsonl\n` +
      `  source_sha256 ${sourceSha256}\n` +
      `  corpus_sha256 ${manifest.corpus_sha256}\n` +
      `  summary length p50=${manifest.summary_length.p50} max=${manifest.summary_length.max} truncated=${truncated} (${manifest.summary_truncated_pct}%)\n` +
      `  download floor by rank: ${JSON.stringify(manifest.tier_download_floor)}`,
  );
}

main();
