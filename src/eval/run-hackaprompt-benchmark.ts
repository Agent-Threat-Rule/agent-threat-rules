#!/usr/bin/env npx tsx
/**
 * HackAPrompt Benchmark Runner
 *
 * Measures ATR recall on the pinned 4,780-sample HackAPrompt set produced by
 * scripts/hackaprompt-to-corpus.py (dataset revision, seed and row indices in
 * data/hackaprompt/hackaprompt-corpus.manifest.json). One command:
 *
 *   npm run eval:hackaprompt
 *
 * which regenerates the corpus at the pinned revision (HuggingFace access to
 * the gated dataset required) and then runs this file. The runner refuses a
 * corpus whose SHA-256 differs from the manifest.
 *
 * Every figure is per lane. The headline (metrics.recall) is the hunt lane,
 * as for every other source; breakdown.lanes carries hunt, alert and enforce
 * side by side and breakdown.enforce_lane carries enforce in the shared shape.
 * Because rules were written from this corpus, the runner also measures it
 * with those rules removed (breakdown.in_sample_ablation). That ablation is
 * the reference to cite beside the headline; it approximates an out-of-sample
 * figure but is not one (see data/hackaprompt/METHOD.md).
 *
 * HackAPrompt is an all-adversarial corpus: recall is defined, precision and
 * FP rate are not (they are recorded as the schema's convention values).
 *
 * @module agent-threat-rules/eval/run-hackaprompt-benchmark
 */

import { execFileSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { HACKAPROMPT_OUTCOME_CATEGORY, loadHackaPromptCorpus, getHackaPromptCorpusStats } from './hackaprompt-corpus.js';
import { embeddingProvenance } from './embedding-provenance.js';
import { enforceLaneFromEval, runEval, type EvalConfig } from './eval-harness.js';
import {
  HACKAPROMPT_BATCH_0512_RULE_IDS,
  loadManifest,
  rulesDirWithout,
  rulesNamingHackaPrompt,
  verifyCorpusAgainstManifest,
} from './hackaprompt-provenance.js';
import { measurementInputFromEvalReport } from '../measurement/from-eval-harness.js';
import { writeMeasurement } from '../measurement/write.js';
import type { Lane } from '../quality/rule-contract.js';

const SOURCE_URL = 'https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset';
const REPRODUCE =
  'git checkout <atr_commit> (the measured tree; its rules/ tree is breakdown.provenance.rules_tree_sha), ' +
  'then: npm ci && npm run eval:hackaprompt ' +
  '(= python3 scripts/hackaprompt-to-corpus.py, which checks the re-drawn sample against the committed manifest ' +
  'and the parquet file against its pinned sha256 before writing the corpus, && npx tsx src/eval/run-hackaprompt-benchmark.ts)';

/** The ablation cited beside the headline (breakdown.in_sample_ablation[reference]). */
const ABLATION_REFERENCE = 'without_rules_naming_source';

const ABLATION_NOTE =
  'Ablation reference, not an out-of-sample result. Rules whose YAML names HackAPrompt were written from ' +
  'this corpus (several from this exact 4,780-sample set), so recall with them loaded is in-sample. ' +
  `${ABLATION_REFERENCE} re-measures the same samples with every such rule removed; it is the figure to cite ` +
  'beside the headline. It approximates an out-of-sample figure without guaranteeing one: a rule whose YAML ' +
  'does not name HackAPrompt may still have been tuned on these samples or on near-duplicates of them, and ' +
  'the removed rules may also catch attacks they were not mined from. without_batch_2026_05_12 removes only ' +
  'ATR-2026-00452..00456, the batch mined from this exact sample on 2026-05-12.';

interface LaneFigure {
  readonly lane: Lane;
  readonly detected: number;
  readonly attacks: number;
  readonly recall: number;
  readonly rules_in_lane: number;
}

type Run = Awaited<ReturnType<typeof runEval>>;

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

function figure(run: Run): LaneFigure {
  const { tp, fn } = run.report.overall.confusion;
  return { lane: run.lane, detected: tp, attacks: tp + fn, recall: tp / (tp + fn), rules_in_lane: run.rulesInLane };
}

function log(label: string, f: LaneFigure): void {
  console.log(`  ${label.padEnd(34)} ${f.lane.padEnd(8)} ${f.detected}/${f.attacks} = ${pct(f.recall)} (${f.rules_in_lane} rules in lane)`);
}

function rulesTreeSha(base: string): string {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD:rules'], { cwd: base, encoding: 'utf-8' }).trim();
  } catch {
    return 'unknown';
  }
}

async function ablation(
  base: Omit<EvalConfig, 'lane' | 'rulesDir'>,
  rulesDir: string,
  ids: readonly string[],
  description: string
) {
  const { dir, removed } = rulesDirWithout(rulesDir, ids);
  const hunt = figure(await runEval({ ...base, rulesDir: dir, lane: 'hunt' }));
  const enforce = figure(await runEval({ ...base, rulesDir: dir, lane: 'enforce' }));
  log(`without ${removed.length} rules: ${description}`, hunt);
  log(`without ${removed.length} rules: ${description}`, enforce);
  return { description, removed_rule_ids: removed, lanes: { hunt, enforce } };
}

async function main(): Promise<void> {
  const base = resolve(join(import.meta.dirname ?? '.', '..', '..'));
  const rulesDir = join(base, 'rules');
  const embeddingsPath = join(base, 'data', 'attack-embeddings.json');
  const dataPath = join(base, 'data', 'hackaprompt', 'hackaprompt-corpus.json');
  const manifestPath = join(base, 'data', 'hackaprompt', 'hackaprompt-corpus.manifest.json');
  const outputPath = join(base, 'data', 'hackaprompt', 'hackaprompt-eval-report.json');

  const manifest = loadManifest(manifestPath);
  const corpusSha = verifyCorpusAgainstManifest(dataPath, manifest);
  const corpus = loadHackaPromptCorpus(dataPath);
  const stats = getHackaPromptCorpusStats(corpus);
  if (stats.total !== manifest.samples) {
    throw new Error(`corpus has ${stats.total} samples, manifest says ${manifest.samples}`);
  }
  console.log('\n=== HackAPrompt Benchmark -- ATR Evaluation ===\n');
  console.log(`Dataset: ${manifest.dataset_id}@${manifest.dataset_revision}`);
  console.log(`Corpus:  ${stats.total} samples, sha256 ${corpusSha}`);

  const shared = { corpus, embeddingsPath } as const;
  const hunt = await runEval({
    ...shared,
    rulesDir,
    lane: 'hunt',
    outputPath,
    thresholds: { minRecall: 0.1, maxFpRate: 1.0, minF1: 0.0, maxP95LatencyMs: 200 },
  });
  const alert = await runEval({ ...shared, rulesDir, lane: 'alert' });
  const enforceRun = await runEval({ ...shared, rulesDir, lane: 'enforce' });
  const enforceLane = enforceLaneFromEval(enforceRun, hunt);
  for (const r of [alert, enforceRun]) {
    if (r.eventShape !== hunt.eventShape || r.tiersUsed.join('+') !== hunt.tiersUsed.join('+')) {
      throw new Error(`the ${r.lane} run differs from the hunt run in event shape or tiers`);
    }
  }
  console.log(`\nTiers: ${hunt.tiersUsed.join(' + ')}   Event shape: ${hunt.eventShape}`);
  const lanes = { hunt: figure(hunt), alert: figure(alert), enforce: figure(enforceRun) };
  for (const f of Object.values(lanes)) log('all rules', f);

  const namingHap = rulesNamingHackaPrompt(rulesDir);
  const inSample = {
    note: ABLATION_NOTE,
    reference: ABLATION_REFERENCE,
    [ABLATION_REFERENCE]: await ablation(shared, rulesDir, namingHap,
      'every rule whose YAML text names HackAPrompt'),
    without_batch_2026_05_12: await ablation(shared, rulesDir, HACKAPROMPT_BATCH_0512_RULE_IDS,
      'ATR-2026-00452..00456 (commit e9efefdd)'),
  };

  // The embedding tier's contribution: the hunt lane once more, regex tier only.
  const noEmbedding = figure(await runEval({ corpus, rulesDir, lane: 'hunt', enableEmbedding: false }));
  log('all rules, embedding tier off', noEmbedding);
  const embedding = hunt.tiersUsed.includes('tier2.5-embedding')
    ? await embeddingProvenance(embeddingsPath, 'data/attack-embeddings.json')
    : null;

  const input = measurementInputFromEvalReport(hunt.report, {
    source: 'hackaprompt',
    source_version: 'v1',
    source_url: `${SOURCE_URL}/tree/${manifest.dataset_revision}`,
    enforceLane,
    notes:
      'HackAPrompt competition dataset (Schulhoff et al., EMNLP 2023). All samples adversarial, so ' +
      'precision/fp_rate are convention values, not results. metrics.recall is the hunt lane (every ' +
      'maturity); breakdown.lanes gives hunt/alert/enforce. breakdown.in_sample_ablation.' + ABLATION_REFERENCE +
      ' is the ablation reference to cite beside it: the same samples without the rules whose YAML names ' +
      'HackAPrompt (an approximation of out-of-sample recall, not a guarantee of it). breakdown.by_category ' +
      "groups samples by HackAPrompt's `correct` field (whether the attack succeeded against its target model " +
      "in the competition), not by attack type; breakdown.by_difficulty buckets the competition level " +
      '(0-2 easy, 3-6 medium, 7-10 hard). Sample set: breakdown.provenance (pinned dataset revision, ' +
      `seed, row indices in data/hackaprompt/hackaprompt-corpus.manifest.json). Event shape: ${hunt.eventShape}; ` +
      `tiers: ${hunt.tiersUsed.join('+')}. Reproduce: ${REPRODUCE}. Method: data/hackaprompt/METHOD.md.`,
  });
  const { measurementPath } = writeMeasurement(
    {
      ...input,
      source_commit: manifest.dataset_revision,
      breakdown: {
        ...input.breakdown,
        lanes,
        by_category_field: {
          field: 'correct',
          meaning:
            "HackAPrompt's `correct`: the submission made its target model produce the level's target output, " +
            'i.e. the attack succeeded in the competition. Not an attack type.',
          categories: HACKAPROMPT_OUTCOME_CATEGORY,
        },
        in_sample_ablation: inSample,
        precision_not_citable: {
          reason:
            'HackAPrompt is 100% adversarial: there is no benign population, so precision and FP rate are undefined. ' +
            'metrics.precision and metrics.fp_rate are the convention values the schema requires, not results; ' +
            'data/stats.json projects precision, F1 and FP rate as null.',
          benign_samples: 0,
        },
        provenance: {
          dataset_id: manifest.dataset_id,
          dataset_revision: manifest.dataset_revision,
          parquet_sha256: manifest.parquet_sha256,
          rows_total: manifest.rows_total,
          selection: manifest.selection,
          filter: manifest.filter,
          dropped_short_or_empty: manifest.dropped_short_or_empty,
          corpus_sha256: corpusSha,
          sample_ids_sha256: manifest.sample_ids_sha256,
          manifest: 'data/hackaprompt/hackaprompt-corpus.manifest.json',
          rules_tree_sha: rulesTreeSha(base),
          event_shape: hunt.eventShape,
          tiers: hunt.tiersUsed,
          embedding,
          hunt_without_embedding_tier: noEmbedding,
          reproduce: REPRODUCE,
        },
      },
    },
    { force: true }
  );
  console.log(`\nMeasurement: ${measurementPath}`);
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
