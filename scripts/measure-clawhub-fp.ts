/**
 * Scan the ClawHub benign corpus with the full ATR rule set and record, per
 * sample and per event shape, exactly which rules fired.
 *
 * THE ONE THING THIS SCRIPT REFUSES TO DO
 *
 * It never reports a single "false positive rate". It reports a flagged rate
 * PER SHAPE, because the shape decides which rules the engine even admits, and
 * it emits the raw per-sample rule ids so every downstream number is derivable
 * rather than asserted. It also never calls a flagged sample a false positive:
 * the corpus is a full registry crawl, so some flags may be correct. Triage is
 * a separate, human step.
 *
 * SHARDING
 *
 * ~95ms per sample across three shapes on 784 rules, so a single process needs
 * about an hour. `--shard i --of n` takes every n-th sample (stride, not block,
 * so each shard sees the same download distribution and a partial run is still
 * representative). scripts/report-clawhub-fp.ts merges the shard files.
 *
 * Run: npx tsx scripts/measure-clawhub-fp.ts --shard 0 --of 10 --variant summary
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from '../src/engine.js';
import { clawhubShapes, CLAWHUB_SHAPE_NAMES, type ClawhubShapeName } from './lib/clawhub-shapes.js';
import { sampleText, TEXT_VARIANTS, type ClawhubSample, type TextVariant } from './lib/clawhub-corpus.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS = join(REPO_ROOT, 'data/measurements/clawhub-benign/corpus.jsonl');
const RULES_DIR = join(REPO_ROOT, 'rules');

interface Args {
  readonly shard: number;
  readonly of: number;
  readonly variant: TextVariant;
  readonly outDir: string;
  readonly limit: number | null;
  /** Override the corpus file. Used by the positive-path check below. */
  readonly corpus: string;
}

function parseArgs(argv: readonly string[]): Args {
  const get = (flag: string): string | null => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
  };
  const of = Number(get('--of') ?? '1');
  const shard = Number(get('--shard') ?? '0');
  const variant = (get('--variant') ?? 'summary') as TextVariant;
  const limitRaw = get('--limit');
  if (!Number.isInteger(of) || of < 1) throw new Error(`--of must be a positive integer, got ${of}`);
  if (!Number.isInteger(shard) || shard < 0 || shard >= of) {
    throw new Error(`--shard must be in [0, ${of}), got ${shard}`);
  }
  if (!TEXT_VARIANTS.includes(variant)) {
    throw new Error(`--variant must be one of ${TEXT_VARIANTS.join('|')}, got ${variant}`);
  }
  return Object.freeze({
    shard,
    of,
    variant,
    outDir: get('--out') ?? join(REPO_ROOT, 'data/measurements/clawhub-benign', variant),
    limit: limitRaw === null ? null : Number(limitRaw),
    corpus: get('--corpus') ?? CORPUS,
  });
}

function loadCorpus(path: string, limit: number | null): readonly ClawhubSample[] {
  const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.length > 0);
  const all = lines.map((l) => JSON.parse(l) as ClawhubSample);
  return limit === null ? all : all.slice(0, limit);
}

/** Flagged sample: which rules fired on which shapes. Absent shapes fired none. */
interface FlaggedSample {
  readonly id: string;
  readonly downloads: number;
  readonly stars: number;
  readonly rank: number;
  readonly byShape: Readonly<Partial<Record<ClawhubShapeName, readonly string[]>>>;
}

interface ShardResult {
  readonly shard: number;
  readonly of: number;
  readonly variant: TextVariant;
  readonly lane: string;
  readonly rulesLoaded: number;
  readonly scanned: number;
  readonly elapsedMs: number;
  readonly flaggedByShape: Record<ClawhubShapeName, number>;
  readonly flaggedAnyShape: number;
  readonly flagged: readonly FlaggedSample[];
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const engine = new ATREngine({ rulesDir: RULES_DIR, lane: 'hunt' });
  // Without this the engine holds zero compiled patterns and every rate is 0.
  const rulesLoaded = await engine.loadRules();
  if (rulesLoaded < 700) throw new Error(`only ${rulesLoaded} rules loaded from ${RULES_DIR}`);

  const corpus = loadCorpus(args.corpus, args.limit);
  const flagged: FlaggedSample[] = [];
  const flaggedByShape: Record<string, number> = Object.fromEntries(
    CLAWHUB_SHAPE_NAMES.map((n) => [n, 0]),
  );
  let scanned = 0;
  const started = Date.now();

  for (let rank = args.shard; rank < corpus.length; rank += args.of) {
    const sample = corpus[rank];
    const text = sampleText(sample, args.variant);
    scanned += 1;
    const byShape: Partial<Record<ClawhubShapeName, readonly string[]>> = {};
    for (const shape of clawhubShapes(text)) {
      const ids = [...new Set(engine.evaluate(shape.event).map((m) => m.rule.id))].sort();
      if (ids.length > 0) {
        byShape[shape.name] = Object.freeze(ids);
        flaggedByShape[shape.name] += 1;
      }
    }
    if (Object.keys(byShape).length > 0) {
      flagged.push(
        Object.freeze({
          id: sample.id,
          downloads: sample.downloads,
          stars: sample.stars,
          rank,
          byShape: Object.freeze(byShape),
        }),
      );
    }
  }

  const result: ShardResult = Object.freeze({
    shard: args.shard,
    of: args.of,
    variant: args.variant,
    lane: engine.getLane(),
    rulesLoaded,
    scanned,
    elapsedMs: Date.now() - started,
    flaggedByShape: flaggedByShape as Record<ClawhubShapeName, number>,
    flaggedAnyShape: flagged.length,
    flagged: Object.freeze(flagged),
  });

  mkdirSync(args.outDir, { recursive: true });
  const out = join(args.outDir, `shard-${args.shard}-of-${args.of}.json`);
  writeFileSync(out, JSON.stringify(result, null, 1) + '\n', 'utf8');
  console.log(
    `shard ${args.shard}/${args.of} variant=${args.variant} rules=${rulesLoaded} ` +
      `scanned=${scanned} flaggedAny=${flagged.length} ` +
      `perShape=${JSON.stringify(flaggedByShape)} ${(result.elapsedMs / 1000).toFixed(1)}s -> ${out}`,
  );
}

main().catch((err) => {
  console.error('measure-clawhub-fp FAILED:', err);
  process.exit(1);
});
