/**
 * HackAPrompt Corpus Loader
 *
 * Reads the HackAPrompt-format sample JSON (text/category/label/source/language)
 * produced by scripts/hackaprompt-to-corpus.py and converts each row into the
 * CorpusSample shape used by the ATR eval harness.
 *
 * HackAPrompt is an all-adversarial corpus: every sample is an attempt to
 * subvert the system prompt. We therefore only measure recall against this
 * dataset; precision/FP rate is undefined here. For combined precision+recall
 * use this corpus alongside a benign source (PINT, real-traffic).
 *
 * @module agent-threat-rules/eval/hackaprompt-corpus
 */

import { readFileSync } from 'node:fs';
import type { CorpusSample } from './corpus.js';

interface RawHackaPromptSample {
  readonly id: string;
  readonly text: string;
  readonly category: string;
  readonly label: boolean;
  readonly source: string;
  readonly language: string;
  readonly metadata?: {
    readonly level?: number;
    readonly correct?: boolean;
    readonly model?: string;
  };
}

/**
 * The two groups breakdown.by_category reports. HackAPrompt's `correct` field
 * records whether the submission made its target model produce the level's
 * target output, i.e. whether the attack succeeded in the competition. It is
 * not an attack type. The corpus file's own `category` ("jailbreak" /
 * "prompt-injection") is a label PR #51 derived from that same field; it stays
 * in the file so the corpus keeps the digest the manifest pins, and is not used.
 */
export const HACKAPROMPT_OUTCOME_CATEGORY = {
  succeeded: 'competition-outcome:succeeded',
  failed: 'competition-outcome:failed',
} as const;

function assignDifficulty(level: number): 'easy' | 'medium' | 'hard' {
  if (level <= 2) return 'easy';
  if (level <= 6) return 'medium';
  return 'hard';
}

export function loadHackaPromptCorpus(dataPath: string): readonly CorpusSample[] {
  const raw: readonly RawHackaPromptSample[] = JSON.parse(
    readFileSync(dataPath, 'utf-8')
  );

  return raw.map((sample): CorpusSample => {
    const level = sample.metadata?.level ?? 5;
    return {
      id: sample.id,
      text: sample.text,
      category: sample.metadata?.correct === true
        ? HACKAPROMPT_OUTCOME_CATEGORY.succeeded
        : HACKAPROMPT_OUTCOME_CATEGORY.failed,
      expectedDetection: sample.label,
      eventType: 'llm_input',
      tier: 'any',
      difficulty: assignDifficulty(level),
      fields: {
        text: sample.text,
        prompt: sample.text,
        user_input: sample.text,
      },
    };
  });
}

export function getHackaPromptCorpusStats(corpus: readonly CorpusSample[]) {
  const stats = {
    total: corpus.length,
    attacks: 0,
    benign: 0,
    byCategory: {} as Record<string, number>,
    byDifficulty: {} as Record<string, number>,
  };
  for (const s of corpus) {
    if (s.expectedDetection) stats.attacks++;
    else stats.benign++;
    stats.byCategory[s.category] = (stats.byCategory[s.category] ?? 0) + 1;
    stats.byDifficulty[s.difficulty] = (stats.byDifficulty[s.difficulty] ?? 0) + 1;
  }
  return stats;
}
