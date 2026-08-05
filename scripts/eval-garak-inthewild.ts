#!/usr/bin/env npx tsx
/**
 * eval-garak-inthewild.ts
 *
 * Run the ATR engine against NVIDIA garak's in-the-wild jailbreak corpus
 * — the narrow, jailbreak-only subset that produces the headline `garak`
 * recall claim ATR publishes externally.
 *
 * Corpus: data/test-corpora/garak-full/inthewild.json
 *   - Single file with {family: "inthewild", count, prompts: string[]}
 *   - Extracted from upstream NVIDIA/garak.
 *
 * Writes a Measurement under source `garak` (the headline). NOT to be
 * confused with `garak-full` (broader corpus, 23 families; see
 * scripts/run-garak-full-benchmark.ts).
 *
 * No Python required — the corpus file is already extracted into the repo
 * by an earlier garak extraction pass. To refresh from upstream garak, run
 * the legacy scripts/eval-garak.sh (which requires `pip install garak`).
 *
 * EVENT SHAPE — read before touching the number this writes
 *
 * Until 2026-08-05 this script built `{ type: 'llm_io' }`. `llm_io` is a rule
 * SOURCE, not an `AgentEventType`; `EVENT_TYPE_TO_SOURCE` in src/engine.ts has
 * no entry for it, so `eventSourceType` was `undefined` and the engine skipped
 * source-type filtering altogether — every rule of every source ran against an
 * event carrying only `user_input`. The script's own comment said it was
 * evaluating the llm_input channel; it was not. `tsc` reports it as
 * TS2322 ("Type '\"llm_io\"' is not assignable to type 'AgentEventType'"), and
 * nobody saw it because tsconfig.json only included `src/**`.
 *
 * The shapes now come from scripts/lib/corpus-event.ts, the single module that
 * owns event construction, and this script reports TWO numbers:
 *
 *   headline  — promptChannelShapes(): llm_input + tool_response, the two
 *               channels src/hook-handler.ts can actually deliver a prompt on.
 *               This is what the Measurement records.
 *   canonical — matchedRuleIds(): the wide FP-parity shape set, including
 *               engine.scanSkill(). Recorded in `breakdown` for comparison
 *               only. A garak prompt never arrives as a SKILL.md, so crediting
 *               detections through that path would inflate a corpus that is
 *               100% adversarial and can therefore never pay the FP back.
 *
 * Usage:
 *   npx tsx scripts/eval-garak-inthewild.ts
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from '../src/engine.js';
import { readATRVersion, writeMeasurement } from '../src/measurement/write.js';
import { matchedRuleIds, promptChannelShapes } from './lib/corpus-event.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const CORPUS_FILE = resolve(REPO_ROOT, 'data/test-corpora/garak-full/inthewild.json');

interface InTheWildCorpus {
  family: 'inthewild';
  count: number;
  prompts: string[];
}

async function main(): Promise<void> {
  if (!existsSync(CORPUS_FILE)) {
    console.error(`Corpus not found: ${CORPUS_FILE}`);
    console.error('Provision the file or run scripts/eval-garak.sh (requires pip install garak).');
    process.exit(1);
  }

  console.log('Loading ATR engine...');
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  const ruleCount = await engine.loadRules();
  console.log(`Loaded ${ruleCount} rules`);

  const corpus = JSON.parse(readFileSync(CORPUS_FILE, 'utf-8')) as InTheWildCorpus;
  console.log(`\nCorpus: garak inthewild_jailbreak_llms (${corpus.prompts.length} prompts)`);

  let matched = 0;
  let matchedCanonical = 0;
  const missedPrompts: string[] = [];
  // Counted per (prompt, rule) — a rule that fires on both prompt channels is
  // one detection, not two. The legacy hand-maintained report counted raw
  // match objects, which is why its by_severity totals exceeded the prompt
  // count several times over.
  const bySeverity: Record<string, number> = {};
  const ruleHits = new Map<string, { title: string; severity: string; count: number }>();

  for (const prompt of corpus.prompts) {
    // Headline: the two channels production can deliver a prompt on.
    const hits = new Map<string, { title: string; severity: string }>();
    for (const shape of promptChannelShapes(prompt)) {
      for (const m of engine.evaluate(shape.event)) {
        hits.set(m.rule.id, { title: m.rule.title, severity: m.rule.severity });
      }
    }
    if (hits.size > 0) {
      matched += 1;
      for (const [id, meta] of hits) {
        bySeverity[meta.severity] = (bySeverity[meta.severity] ?? 0) + 1;
        const prev = ruleHits.get(id);
        ruleHits.set(id, {
          title: meta.title,
          severity: meta.severity,
          count: (prev?.count ?? 0) + 1,
        });
      }
    } else {
      missedPrompts.push(prompt.slice(0, 150));
    }
    // Comparison only — the wide FP-parity shape set (adds JSON-encoded
    // presentations and the SKILL.md scan path).
    if (matchedRuleIds(engine, prompt).size > 0) {
      matchedCanonical += 1;
    }
  }

  const topRules = [...ruleHits.entries()]
    .map(([id, v]) => ({ id, title: v.title, severity: v.severity, count: v.count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  const total = corpus.prompts.length;
  const recall = total > 0 ? matched / total : 0;
  const canonicalRecall = total > 0 ? matchedCanonical / total : 0;
  const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);

  console.log(`\nResults:`);
  console.log(`  Total prompts: ${total}`);
  console.log(`  Detected:      ${matched}`);
  console.log(`  Missed:        ${missedPrompts.length}`);
  console.log(`  Recall:        ${(recall * 100).toFixed(1)}%   [headline — llm_input + tool_response]`);
  console.log(
    `  Recall (wide): ${(canonicalRecall * 100).toFixed(1)}%   [corpus-event canonical shapes + scanSkill — NOT published]`,
  );

  // Standardized Measurement file (version-pinned, immutable).
  // 100%-adversarial corpus → precision = 1 by construction, fp_rate
  // undefined and recorded as 0 by convention.
  const { measurementPath } = writeMeasurement(
    {
      source: 'garak',
      source_version: `inthewild-jailbreak-corpus-${total}`,
      source_url: 'https://github.com/NVIDIA/garak',
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
        fn: missedPrompts.length,
      },
      breakdown: {
        family: corpus.family,
        first_5_misses: missedPrompts.slice(0, 5),
        by_severity: bySeverity,
        top_rules: topRules,
        event_shapes: 'llm_input + tool_response (scripts/lib/corpus-event.ts promptChannelShapes)',
        wide_shape_recall: canonicalRecall,
        wide_shape_detected: matchedCanonical,
        wide_shape_note:
          'matchedRuleIds() — the wide FP-parity shape set plus engine.scanSkill(). ' +
          'Reported for comparison, NOT published: a garak prompt never reaches production ' +
          'as a SKILL.md, and a 100%-adversarial corpus never pays the false positive back.',
      },
      notes:
        `NVIDIA garak in-the-wild jailbreak corpus (single family: '${corpus.family}'). ` +
        'Each prompt is evaluated on the two production prompt channels — llm_input and ' +
        'tool_response — via scripts/lib/corpus-event.ts. Before 2026-08-05 this harness ' +
        "used type: 'llm_io', which is not an AgentEventType; the engine could not map it to " +
        'a source and skipped source-type filtering entirely, so the pre-2026-08-05 numbers ' +
        'in this series were measured on an unintended shape. ' +
        'Distinct from `garak-full` which covers all 23 probe families. ' +
        '100% adversarial — fp_rate undefined and recorded as 0 by convention.',
    },
    { force: true },
  );
  console.log(`\nMeasurement: ${measurementPath}`);

  // data/garak-benchmark/garak-eval-report.json had NO generator in this repo
  // — only the pip-dependent scripts/eval-garak.sh, which almost nobody runs.
  // So it was maintained by hand, and on 2026-08-04 PR #370 hand-edited it to
  // 595/650 = 91.5% while writing no measurement file at all. A "report" that
  // only a human can produce is not evidence. It is generated here now, from
  // the same run that writes the measurement, so the two can never disagree.
  const reportPath = resolve(REPO_ROOT, 'data/garak-benchmark/garak-eval-report.json');
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(
    reportPath,
    `${JSON.stringify(
      {
        benchmark: 'NVIDIA Garak In-The-Wild Jailbreak Dataset',
        source: 'garak — data/test-corpora/garak-full/inthewild.json',
        generated_by: 'scripts/eval-garak-inthewild.ts',
        date: new Date().toISOString().slice(0, 10),
        atr_version: readATRVersion(),
        rules_loaded: ruleCount,
        event_shapes: 'llm_input + tool_response (scripts/lib/corpus-event.ts promptChannelShapes)',
        dataset: {
          total_prompts: total,
          type: '100% malicious (real-world jailbreaks)',
        },
        results: {
          detected: matched,
          missed: missedPrompts.length,
          recall: Number((recall * 100).toFixed(1)),
        },
        wide_shape_comparison: {
          detected: matchedCanonical,
          recall: Number((canonicalRecall * 100).toFixed(1)),
          note:
            'corpus-event canonical shapes + engine.scanSkill(). Not published — a ' +
            'garak prompt never reaches production as a SKILL.md.',
        },
        by_severity: bySeverity,
        top_rules: topRules,
      },
      null,
      2,
    )}\n`,
  );
  console.log(`Report:      ${reportPath}`);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
