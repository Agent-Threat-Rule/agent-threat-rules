/**
 * Merge the ClawHub measurement shards into one report.
 *
 * REFUSALS BUILT IN
 *   - It aborts unless every shard file of the declared `--of` is present and
 *     the scanned counts sum to the corpus size. A missing shard would deflate
 *     every rate by exactly the amount nobody would notice.
 *   - It never emits a pooled "false positive rate". Rates are per shape and
 *     per download stratum. Flagged samples are called FLAGGED, not FP, because
 *     the corpus is a full registry crawl and some flags may be true positives.
 *
 * Run: npx tsx scripts/report-clawhub-fp.ts --variant summary --of 10
 */

import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRulesFromDirectory } from '../src/loader.js';
import { CLAWHUB_SHAPE_NAMES, type ClawhubShapeName } from './lib/clawhub-shapes.js';
import { DOWNLOAD_TIERS, type ClawhubSample } from './lib/clawhub-corpus.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = join(REPO_ROOT, 'data/measurements/clawhub-benign');
const RULES_DIR = join(REPO_ROOT, 'rules');

interface FlaggedSample {
  readonly id: string;
  readonly downloads: number;
  readonly stars: number;
  readonly rank: number;
  readonly byShape: Partial<Record<ClawhubShapeName, readonly string[]>>;
}
interface ShardResult {
  readonly shard: number;
  readonly of: number;
  readonly variant: string;
  readonly lane: string;
  readonly rulesLoaded: number;
  readonly scanned: number;
  readonly flagged: readonly FlaggedSample[];
}

function argOf(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

function readShards(dir: string, of: number): readonly ShardResult[] {
  const present = readdirSync(dir).filter((f) => f.endsWith(`-of-${of}.json`));
  if (present.length !== of) {
    throw new Error(`expected ${of} shard files in ${dir}, found ${present.length}: ${present.join(', ')}`);
  }
  return present.map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')) as ShardResult);
}

function readCorpus(): readonly ClawhubSample[] {
  return readFileSync(join(BASE, 'corpus.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as ClawhubSample);
}

interface RuleMeta {
  readonly title: string;
  readonly severity: string;
  readonly category: string;
  readonly maturity: string;
  readonly status: string;
  readonly scanTarget: string;
}

function ruleIndex(): ReadonlyMap<string, RuleMeta> {
  const map = new Map<string, RuleMeta>();
  for (const r of loadRulesFromDirectory(RULES_DIR)) {
    map.set(r.id, {
      title: r.title ?? '(no title)',
      severity: String(r.severity ?? '?'),
      category: String(r.tags?.category ?? '?'),
      maturity: String(r.maturity ?? '(unset)'),
      status: String(r.status ?? '(unset)'),
      scanTarget: String(r.tags?.scan_target ?? '(unset)'),
    });
  }
  return map;
}

const pct = (n: number, d: number): number => (d === 0 ? 0 : Number(((100 * n) / d).toFixed(3)));

interface ShapeStratum {
  readonly stratum: string;
  readonly samples: number;
  readonly flagged: number;
  readonly flaggedPct: number;
}

function strata(
  corpusSize: number,
  flaggedRanks: ReadonlySet<number>,
): readonly ShapeStratum[] {
  const rows: ShapeStratum[] = [];
  for (const n of DOWNLOAD_TIERS) {
    const size = Math.min(n, corpusSize);
    let hit = 0;
    for (const rank of flaggedRanks) if (rank < size) hit += 1;
    rows.push({ stratum: `top${n}`, samples: size, flagged: hit, flaggedPct: pct(hit, size) });
  }
  rows.push({
    stratum: 'all',
    samples: corpusSize,
    flagged: flaggedRanks.size,
    flaggedPct: pct(flaggedRanks.size, corpusSize),
  });
  return Object.freeze(rows);
}

interface TopRule {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: string;
  readonly maturity: string;
  readonly scanTarget: string;
  readonly flagged: number;
  readonly flaggedPct: number;
  readonly topDownloadHit: number;
  readonly examples: readonly { readonly id: string; readonly downloads: number; readonly summary: string }[];
}

function topRules(
  perRule: ReadonlyMap<string, readonly FlaggedSample[]>,
  meta: ReadonlyMap<string, RuleMeta>,
  corpus: readonly ClawhubSample[],
  corpusSize: number,
  limit: number,
): readonly TopRule[] {
  const byRank = new Map(corpus.map((s, i) => [i, s]));
  return [...perRule.entries()]
    .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([ruleId, hits]) => {
      const m = meta.get(ruleId);
      const ranked = [...hits].sort((a, b) => b.downloads - a.downloads);
      return Object.freeze({
        ruleId,
        title: m?.title ?? '(rule not on disk)',
        severity: m?.severity ?? '?',
        maturity: m?.maturity ?? '?',
        scanTarget: m?.scanTarget ?? '?',
        flagged: hits.length,
        flaggedPct: pct(hits.length, corpusSize),
        topDownloadHit: ranked[0]?.downloads ?? 0,
        examples: Object.freeze(
          ranked.slice(0, 3).map((h) => ({
            id: h.id,
            downloads: h.downloads,
            summary: (byRank.get(h.rank)?.summary ?? '').slice(0, 220),
          })),
        ),
      });
    });
}

function main(): void {
  const variant = argOf('--variant', 'summary');
  const of = Number(argOf('--of', '10'));
  const limit = Number(argOf('--top', '20'));
  const dir = join(BASE, variant);

  const shards = readShards(dir, of);
  const corpus = readCorpus();
  const scanned = shards.reduce((a, s) => a + s.scanned, 0);
  if (scanned !== corpus.length) {
    throw new Error(`shards scanned ${scanned} samples but corpus has ${corpus.length}`);
  }
  const rulesLoaded = new Set(shards.map((s) => s.rulesLoaded));
  if (rulesLoaded.size !== 1) {
    throw new Error(`shards disagree on rulesLoaded: ${[...rulesLoaded].join(', ')}`);
  }
  const lanes = new Set(shards.map((s) => s.lane));
  if (lanes.size !== 1) throw new Error(`shards disagree on lane: ${[...lanes].join(', ')}`);

  const meta = ruleIndex();
  const allFlagged = shards.flatMap((s) => s.flagged);
  const report: Record<string, unknown> = {
    corpus: 'clawhub-benign',
    variant,
    generated: new Date().toISOString(),
    rulesLoaded: [...rulesLoaded][0],
    lane: [...lanes][0],
    samples: corpus.length,
    shards: of,
    caveat:
      'FLAGGED, not false-positive. The corpus is a full registry crawl, not a curated benign set. ' +
      'Text is the registry description field (median 159 chars, 42.9% truncated), not SKILL.md bodies.',
  };

  const anyRanks = new Set(allFlagged.map((f) => f.rank));
  report.anyShape = {
    flagged: anyRanks.size,
    flaggedPct: pct(anyRanks.size, corpus.length),
    strata: strata(corpus.length, anyRanks),
  };

  const perShape: Record<string, unknown> = {};
  for (const shape of CLAWHUB_SHAPE_NAMES) {
    const hits = allFlagged.filter((f) => (f.byShape[shape]?.length ?? 0) > 0);
    const ranks = new Set(hits.map((h) => h.rank));
    const perRule = new Map<string, FlaggedSample[]>();
    for (const h of hits) {
      for (const id of h.byShape[shape] ?? []) {
        const list = perRule.get(id) ?? [];
        list.push(h);
        perRule.set(id, list);
      }
    }
    const enforceRuleIds = [...perRule.keys()].filter((id) => meta.get(id)?.maturity === 'stable');
    const enforceRanks = new Set(
      hits.filter((h) => (h.byShape[shape] ?? []).some((id) => meta.get(id)?.maturity === 'stable')).map((h) => h.rank),
    );
    perShape[shape] = {
      flagged: ranks.size,
      flaggedPct: pct(ranks.size, corpus.length),
      distinctRulesFiring: perRule.size,
      strata: strata(corpus.length, ranks),
      enforceLane: {
        note: 'maturity=stable only — the auto-block lane. Derived from the hunt-lane run by rule maturity.',
        distinctRulesFiring: enforceRuleIds.length,
        flagged: enforceRanks.size,
        flaggedPct: pct(enforceRanks.size, corpus.length),
        strata: strata(corpus.length, enforceRanks),
      },
      topRules: topRules(perRule, meta, corpus, corpus.length, limit),
    };
  }
  report.byShape = perShape;

  const out = join(dir, 'report.json');
  writeFileSync(out, JSON.stringify(report, null, 2) + '\n', 'utf8');
  console.log(`report -> ${out}`);
  console.log(
    `samples=${corpus.length} rules=${[...rulesLoaded][0]} lane=${[...lanes][0]} anyShapeFlagged=${anyRanks.size} (${pct(anyRanks.size, corpus.length)}%)`,
  );
  for (const shape of CLAWHUB_SHAPE_NAMES) {
    const s = perShape[shape] as { flagged: number; flaggedPct: number; distinctRulesFiring: number; enforceLane: { flagged: number; flaggedPct: number } };
    console.log(
      `  ${shape.padEnd(16)} flagged=${String(s.flagged).padStart(6)} (${s.flaggedPct}%) rulesFiring=${s.distinctRulesFiring} | enforce-lane flagged=${s.enforceLane.flagged} (${s.enforceLane.flaggedPct}%)`,
    );
  }
}

main();
