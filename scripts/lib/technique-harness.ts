/**
 * scripts/lib/technique-harness.ts
 *
 * The measurement half of the technique-first pilot (issue #848): given which
 * corpora a rule's author looked at, which attack hits count as evidence, how
 * they group by derived family, and how benign hits are reported. The engine
 * run lives in scripts/measure-technique-rule.ts; this module is the part a
 * reviewer has to trust, kept free of I/O so it can be tested directly.
 *
 * It reuses fn-mine's notions unchanged (scripts/lib/fn-mine-generalization.ts):
 * sameFamily / familyOf for derived corpora and sampleKey for republished
 * samples. It does not fork them, so it inherits their known limitations:
 *
 * - The family list (DERIVED_FROM) is maintained by hand. A corpus derived from
 *   another that nobody listed counts as an independent family.
 * - sampleKey compares only the first SAMPLE_KEY_CHARS characters, case and
 *   whitespace folded. A payload that a corpus wraps in new text, or that
 *   starts at a different offset, is not recognised as the same sample.
 * - Every vendored corpus is a set of bare texts. The event type each is
 *   presented as is an assignment (the corpus's registered shape), not an
 *   observation, so recall here does not show that a channel property helps.
 */
import { familyOf, sameFamily, sampleKey } from './fn-mine-generalization.js';

export interface CorpusHits {
  readonly id: string;
  /** The event type the corpus is presented to the engine as. */
  readonly shape: string;
  readonly total: number;
  /** The texts the rule fired on. */
  readonly hits: readonly string[];
}

export interface FamilyRecall {
  readonly family: string;
  /** Corpus id -> distinct hits counted for it. */
  readonly corpora: Readonly<Record<string, number>>;
  /** Distinct hits across the family (one sample counted once even if several corpora hold it). */
  readonly distinct: number;
}

export interface RecallReport {
  /** Corpora left out: the ones looked at and their derived families. */
  readonly excluded: readonly string[];
  /** Hits dropped because a looked-at corpus holds the same sample (sampleKey). */
  readonly droppedAsRepublished: number;
  readonly families: readonly FamilyRecall[];
}

/** Every corpus that cannot count as evidence: the looked-at ones and their families. */
export function excludedCorpora(lookedAt: readonly string[]): ReadonlySet<string> {
  const out = new Set<string>();
  for (const id of lookedAt) for (const member of sameFamily(id)) out.add(member);
  return out;
}

/**
 * Hits grouped by derived family, with the looked-at corpora, their families,
 * and any hit whose sampleKey a looked-at corpus also holds left out.
 */
export function familyRecall(
  attacks: readonly CorpusHits[],
  lookedAt: readonly string[],
  lookedAtTexts: readonly string[],
): RecallReport {
  const excluded = excludedCorpora(lookedAt);
  const seen = new Set(lookedAtTexts.map(sampleKey));
  const byFamily = new Map<string, { corpora: Record<string, number>; keys: Set<string> }>();
  let dropped = 0;
  for (const c of attacks) {
    if (excluded.has(c.id)) continue;
    const family = familyOf(c.id);
    const entry = byFamily.get(family) ?? { corpora: {}, keys: new Set<string>() };
    const keys = new Set<string>();
    for (const t of c.hits) {
      const key = sampleKey(t);
      if (seen.has(key)) {
        dropped += 1;
        continue;
      }
      keys.add(key);
    }
    if (keys.size > 0) {
      entry.corpora[c.id] = keys.size;
      for (const k of keys) entry.keys.add(k);
      byFamily.set(family, entry);
    }
  }
  const families = [...byFamily]
    .map(([family, e]) => ({ family, corpora: e.corpora, distinct: e.keys.size }))
    .sort((a, b) => b.distinct - a.distinct || a.family.localeCompare(b.family));
  return { excluded: [...excluded].sort(), droppedAsRepublished: dropped, families };
}

export interface BenignResult {
  readonly id: string;
  readonly shape: string;
  readonly total: number;
  readonly hits: readonly string[];
}

/** "0 of N" per benign corpus, worst first, with up to `examples` hits each. */
export function benignLines(results: readonly BenignResult[], examples = 2): readonly string[] {
  return [...results]
    .sort((a, b) => b.hits.length - a.hits.length || a.id.localeCompare(b.id))
    .flatMap((r) => [
      `  ${r.id} (${r.shape}): ${r.hits.length} of ${r.total}`,
      ...r.hits.slice(0, examples).map((t) => `      e.g. ${JSON.stringify(t.replace(/\s+/g, ' ').slice(0, 140))}`),
    ]);
}

/**
 * The pilot's bar (#848): hits in at least two derived families other than
 * the excluded ones, and no hit on any benign corpus. fn-mine's own gate needs
 * one out-of-sample hit in total, which is weaker on purpose.
 */
export function meetsPilotBar(recall: RecallReport, benign: readonly BenignResult[]): boolean {
  return recall.families.length >= 2 && benign.every((b) => b.hits.length === 0);
}
