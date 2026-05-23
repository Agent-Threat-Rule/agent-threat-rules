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
 * Usage:
 *   npx tsx scripts/eval-garak-inthewild.ts
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
  const missedPrompts: string[] = [];
  for (const prompt of corpus.prompts) {
    // Each prompt is evaluated as BOTH llm_input and tool_response (mirrors
    // scripts/eval-garak.sh) since the in-the-wild jailbreak corpus has
    // prompts that may trigger detectors at either ingestion side.
    const eventLlm: AgentEvent = {
      type: 'llm_io',
      content: prompt,
      timestamp: new Date().toISOString(),
      fields: { user_input: prompt },
    };
    const eventTool: AgentEvent = {
      type: 'mcp_exchange',
      content: prompt,
      timestamp: new Date().toISOString(),
      fields: { tool_response: prompt },
    };
    const matches = [...engine.evaluate(eventLlm), ...engine.evaluate(eventTool)];
    if (matches.length > 0) {
      matched += 1;
    } else {
      missedPrompts.push(prompt.slice(0, 150));
    }
  }

  const total = corpus.prompts.length;
  const recall = total > 0 ? matched / total : 0;
  const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);

  console.log(`\nResults:`);
  console.log(`  Total prompts: ${total}`);
  console.log(`  Detected:      ${matched}`);
  console.log(`  Missed:        ${missedPrompts.length}`);
  console.log(`  Recall:        ${(recall * 100).toFixed(1)}%`);

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
      },
      notes:
        `NVIDIA garak in-the-wild jailbreak corpus (single family: '${corpus.family}'). ` +
        'Each prompt is evaluated as both llm_io and mcp_exchange to mirror the original eval-garak.sh behavior. ' +
        'Distinct from `garak-full` which covers all 23 probe families. ' +
        '100% adversarial — fp_rate undefined and recorded as 0 by convention.',
    },
    { force: true },
  );
  console.log(`\nMeasurement: ${measurementPath}`);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
