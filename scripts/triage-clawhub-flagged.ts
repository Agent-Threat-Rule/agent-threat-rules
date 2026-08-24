/**
 * Dump flagged ClawHub samples for HAND triage.
 *
 * WHY THIS IS A SEPARATE, MANUAL STEP
 *
 * The ClawHub registry crawl is the whole registry, not a curated benign set.
 * The 2026-04 wild scan found confirmed malware published to this same
 * platform. Treating every flag as a false positive and "fixing" the rules
 * would narrow detections using true positives as the evidence — the most
 * expensive mistake available here, because it is invisible afterwards.
 *
 * So this script decides nothing. It prints the sample, its downloads, and
 * which rules fired on which shape, in download order, and a human writes the
 * verdict. Whatever a triager concludes belongs in docs/research/, not here.
 *
 * Run: npx tsx scripts/triage-clawhub-flagged.ts --variant summary --of 10 --top 30
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRulesFromDirectory } from '../src/loader.js';
import type { ClawhubShapeName } from './lib/clawhub-shapes.js';
import type { ClawhubSample } from './lib/clawhub-corpus.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = join(REPO_ROOT, 'data/measurements/clawhub-benign');

interface FlaggedSample {
  readonly id: string;
  readonly downloads: number;
  readonly stars: number;
  readonly rank: number;
  readonly byShape: Partial<Record<ClawhubShapeName, readonly string[]>>;
}

function argOf(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

function main(): void {
  const variant = argOf('--variant', 'summary');
  const of = Number(argOf('--of', '10'));
  const top = Number(argOf('--top', '30'));
  const shape = argOf('--shape', 'any') as ClawhubShapeName | 'any';

  const dir = join(BASE, variant);
  const files = readdirSync(dir).filter((f) => f.endsWith(`-of-${of}.json`));
  if (files.length !== of) throw new Error(`expected ${of} shards in ${dir}, found ${files.length}`);
  const flagged: FlaggedSample[] = files.flatMap(
    (f) => (JSON.parse(readFileSync(join(dir, f), 'utf8')) as { flagged: FlaggedSample[] }).flagged,
  );

  const corpus = readFileSync(join(BASE, 'corpus.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as ClawhubSample);

  const titles = new Map(loadRulesFromDirectory(join(REPO_ROOT, 'rules')).map((r) => [r.id, `${r.severity}/${r.title}`]));

  const selected = flagged
    .filter((f) => shape === 'any' || (f.byShape[shape]?.length ?? 0) > 0)
    .sort((a, b) => b.downloads - a.downloads)
    .slice(0, top);

  console.log(`# Triage queue: top ${selected.length} flagged by downloads (variant=${variant}, shape=${shape})`);
  console.log(`# total flagged samples in this run: ${flagged.length}\n`);
  for (const [i, f] of selected.entries()) {
    const sample = corpus[f.rank];
    console.log(`## ${i + 1}. ${f.id}  downloads=${f.downloads} stars=${f.stars} rank=${f.rank}`);
    console.log(`SUMMARY: ${JSON.stringify(sample.summary)}`);
    for (const [shapeName, ids] of Object.entries(f.byShape)) {
      console.log(`  [${shapeName}] ${(ids as string[]).map((id) => `${id} (${titles.get(id) ?? '?'})`).join('; ')}`);
    }
    console.log('');
  }
}

main();
