/**
 * scripts/lib/tool-output-fp-report.ts
 *
 * The pure half of scripts/report-tool-output-benign-fp.ts: given which rules
 * fired on which benign tool outputs (detectionsByRule in fn-mine-input.ts),
 * how many rules fire, on how many samples, and the worst offenders with a
 * snippet of what they fired on.
 *
 * Informational, not a gate. The benign tool-output corpora gate the FN-mine
 * lane's new candidates only; whether rules already on main must also pass
 * them is a separate decision, and this report is what it would be read from.
 */
import { foldConfusables, normalizeUnicode } from '../../src/engine.js';
import { compileEngineAccurate } from './fn-mine-candidate-gate.js';
import { matchExcerpt } from './fn-mine-recoveries.js';
import type { ATRRule } from '../../src/types.js';

/** What the report needs of a rule. */
export interface RuleInfo {
  readonly id: string;
  readonly title: string;
  readonly maturity: string;
  /** Its regex condition values, as written. */
  readonly regexes: readonly string[];
}

export const SNIPPET_CHARS = 120;

/** The report's view of a loaded rule. */
export function ruleInfo(rule: ATRRule): RuleInfo {
  const conditions = (rule.detection as { conditions?: unknown }).conditions;
  const list = Array.isArray(conditions) ? (conditions as { operator?: unknown; value?: unknown }[]) : [];
  return {
    id: rule.id,
    title: rule.title,
    maturity: rule.maturity ?? 'unset',
    regexes: list.filter((c) => c.operator === 'regex' && typeof c.value === 'string').map((c) => c.value as string),
  };
}

/**
 * About SNIPPET_CHARS of `text` around the first match of one of the rule's
 * regexes, tried on the text as the engine normalizes it and then raw; the
 * start of the text when none matches (a non-regex condition fired).
 */
export function matchSnippet(text: string, rule: RuleInfo): string {
  const variants = [foldConfusables(normalizeUnicode(text)), text];
  for (const value of rule.regexes) {
    const re = compileEngineAccurate(value);
    const hit = re ? variants.find((v) => re.test(v)) : undefined;
    if (re && hit !== undefined) return matchExcerpt(hit, re, SNIPPET_CHARS).replace(/\s+/g, ' ').trim();
  }
  return text.slice(0, SNIPPET_CHARS).replace(/\s+/g, ' ').trim();
}

export interface Offender {
  readonly ruleId: string;
  readonly title: string;
  readonly maturity: string;
  readonly samplesHit: number;
  readonly snippet: string;
}

export interface CorpusFpSection {
  readonly corpus: string;
  readonly samples: number;
  /** Samples at least one rule fires on. */
  readonly samplesFlagged: number;
  /** Rules that fire on at least one sample. */
  readonly rulesFiring: number;
  readonly topOffenders: readonly Offender[];
}

/** One corpus's section: totals, then the `top` rules by samples hit (ties by id). */
export function corpusFpSection(
  corpus: string,
  texts: readonly string[],
  hits: ReadonlyMap<string, readonly number[]>,
  rules: ReadonlyMap<string, RuleInfo>,
  top: number,
): CorpusFpSection {
  const flagged = new Set([...hits.values()].flat());
  const ranked = [...hits.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  const topOffenders = ranked.slice(0, top).map(([id, indices]) => {
    const info = rules.get(id) ?? { id, title: '(not loaded)', maturity: 'unset', regexes: [] };
    return {
      ruleId: id,
      title: info.title,
      maturity: info.maturity,
      samplesHit: indices.length,
      snippet: matchSnippet(texts[indices[0]] ?? '', info),
    };
  });
  return { corpus, samples: texts.length, samplesFlagged: flagged.size, rulesFiring: hits.size, topOffenders };
}

/** The one line the script prints. */
export function summaryLine(rulesLoaded: number, sections: readonly CorpusFpSection[]): string {
  const parts = sections.map((s) => `${s.corpus}: ${s.rulesFiring} rules fire on ${s.samplesFlagged} of ${s.samples} samples`);
  return `[tool-output-benign-fp] ${rulesLoaded} rules on tool_response — ${parts.join('; ')} (informational, not a gate)`;
}
