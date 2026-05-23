#!/usr/bin/env npx tsx
/**
 * eval-small-corpora.ts
 *
 * Runs ATR engine recall evaluation against three small academic / vendor
 * adversarial corpora that share a uniform schema:
 *
 *   - llm-guard (Protect AI input-scanner test fixtures)
 *   - nemo-guardrails (NVIDIA NeMo Guardrails red-team test fixtures)
 *   - promptfoo (promptfoo red-team plugin test fixtures)
 *
 * Each corpus lives at data/test-corpora/<source>/corpus.json with the shape:
 *
 *   { source, source_url, license, extraction_date, count,
 *     attacks: [{ text, label, source_file, attack_family, severity }, ...] }
 *
 * All three corpora are 100% adversarial — precision is 1 by construction,
 * fp_rate is undefined and recorded as 0 by convention in the measurement.
 *
 * Output:
 *   - One Measurement file per source under data/measurements/<source>/
 *   - Per-source recall summary on stdout
 *
 * Usage:
 *   npx tsx scripts/eval-small-corpora.ts
 *   npx tsx scripts/eval-small-corpora.ts --source llm-guard   # one only
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from '../src/engine.js';
import type { AgentEvent } from '../src/types.js';
import { writeMeasurement } from '../src/measurement/write.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const CORPORA_DIR = resolve(REPO_ROOT, 'data/test-corpora');

interface AttackEntry {
  text: string;
  label?: string;
  source_file?: string;
  attack_family?: string;
  severity?: string;
}

interface CorpusFile {
  source: string;
  source_url?: string;
  license?: string;
  extraction_date?: string;
  count: number;
  attacks: AttackEntry[];
}

const KNOWN_SOURCES = ['llm-guard', 'nemo-guardrails', 'promptfoo'] as const;
type KnownSource = (typeof KNOWN_SOURCES)[number];

function parseArgs(): { sources: readonly KnownSource[] } {
  const args = process.argv.slice(2);
  const sourceIdx = args.indexOf('--source');
  if (sourceIdx >= 0 && args[sourceIdx + 1]) {
    const s = args[sourceIdx + 1] as KnownSource;
    if (!KNOWN_SOURCES.includes(s)) {
      console.error(`Unknown source: ${s}. Known: ${KNOWN_SOURCES.join(', ')}`);
      process.exit(2);
    }
    return { sources: [s] };
  }
  return { sources: KNOWN_SOURCES };
}

function loadCorpus(source: KnownSource): CorpusFile | null {
  const path = join(CORPORA_DIR, source, 'corpus.json');
  if (!existsSync(path)) {
    console.error(`::warning::corpus not found at ${path} — skipping ${source}`);
    return null;
  }
  return JSON.parse(readFileSync(path, 'utf-8')) as CorpusFile;
}

async function evalCorpus(
  source: KnownSource,
  corpus: CorpusFile,
  engine: ATREngine,
): Promise<void> {
  let matched = 0;
  const missedSamples: { family: string; text: string }[] = [];
  const byFamily: Record<string, { total: number; matched: number }> = {};

  for (const a of corpus.attacks) {
    const family = a.attack_family ?? 'unknown';
    byFamily[family] = byFamily[family] ?? { total: 0, matched: 0 };
    byFamily[family].total += 1;

    const event: AgentEvent = {
      type: 'llm_io',
      content: a.text,
      timestamp: new Date().toISOString(),
      fields: { user_input: a.text },
    };
    const matches = engine.evaluate(event);
    if (matches.length > 0) {
      matched += 1;
      byFamily[family].matched += 1;
    } else {
      missedSamples.push({ family, text: a.text.slice(0, 200) });
    }
  }

  const total = corpus.attacks.length;
  const recall = total > 0 ? matched / total : 0;
  const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);

  console.log(`\n[${source}] ${matched}/${total} = ${(recall * 100).toFixed(1)}% recall`);
  for (const [fam, stats] of Object.entries(byFamily).sort((a, b) => b[1].total - a[1].total)) {
    const famRecall = stats.matched / stats.total;
    console.log(`  ${fam}: ${stats.matched}/${stats.total} (${(famRecall * 100).toFixed(0)}%)`);
  }
  if (missedSamples.length > 0) {
    console.log(`  ${missedSamples.length} misses (first 3): `);
    for (const m of missedSamples.slice(0, 3)) {
      console.log(`    [${m.family}] ${m.text.slice(0, 100)}…`);
    }
  }

  // Standardized Measurement file (version-pinned, immutable).
  const breakdownFamilies: Record<string, { total: number; matched: number; recall: number }> = {};
  for (const [fam, stats] of Object.entries(byFamily)) {
    breakdownFamilies[fam] = {
      total: stats.total,
      matched: stats.matched,
      recall: stats.total > 0 ? stats.matched / stats.total : 0,
    };
  }
  const sourceVersion = corpus.extraction_date
    ? `corpus-${corpus.extraction_date.slice(0, 10)}`
    : 'corpus-unknown';
  const { measurementPath } = writeMeasurement(
    {
      source,
      source_version: sourceVersion,
      source_url: corpus.source_url,
      samples: total,
      metrics: {
        recall,
        precision: 1,
        f1,
        fp_rate: 0,
      },
      confusion: {
        tp: matched,
        fp: 0,
        tn: 0,
        fn: total - matched,
      },
      breakdown: {
        by_family: breakdownFamilies,
        license: corpus.license,
      },
      notes: `${source} red-team / input-scanner test fixtures extracted from upstream repo. 100% adversarial corpus — fp_rate undefined, recorded as 0 by convention. License: ${corpus.license ?? 'unspecified'}.`,
    },
    { force: true },
  );
  console.log(`  Measurement: ${measurementPath}`);
}

async function main(): Promise<void> {
  const { sources } = parseArgs();

  console.log('Loading ATR engine...');
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  const ruleCount = await engine.loadRules();
  console.log(`Loaded ${ruleCount} rules`);

  for (const source of sources) {
    const corpus = loadCorpus(source);
    if (corpus === null) continue;
    await evalCorpus(source, corpus, engine);
  }

  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
