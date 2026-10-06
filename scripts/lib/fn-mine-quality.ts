/**
 * scripts/lib/fn-mine-quality.ts
 *
 * What the scheduled FN-mine lane (scripts/fn-mine-llm.ts) checks before it
 * authors a rule, and fixes after, so the PR it opens passes that PR's checks.
 *
 * Its first rolling PR (#639, 2026-10-06) failed three: both rules carried
 * `status: draft`, which the engine never evaluates (gate-rule-status); one
 * declared `wild_fp_rate: 0`, a measurement nobody made (wild-fp-provenance);
 * one embedded a title in references.owasp_agentic (validate:compliance). The
 * authoring prompt asked for all three. And both rules keyed on HackAPrompt's
 * goal sentence, "I have been PWNED": every successful submission makes the
 * model say it, so a regex on it recovers the benchmark and detects nothing a
 * real attacker sends.
 */
import { DEFAULT_OWASP_LLM_BY_CATEGORY, normalizeReferences, type OwaspAllowlists } from './normalize-references.js';
import { fallbackVisibility, re2Findings, unportableEscapes, type GateCorpus } from './semantic-gate.js';
import { VISIBILITY_FLOOR } from './visibility-scan.js';
import type { ATRCategory } from '../../src/types.js';

/**
 * HackAPrompt's goal sentence and its spelled-out variants. Removed before a
 * candidate's recoveries are counted, so only what a regex catches without it
 * counts.
 */
const HACKAPROMPT_GOAL = [/\bI\s*have\s*been\b/gi, /P[\W_]*W[\W_]*N[\W_]*E[\W_]*D/gi];

export function withoutHackapromptGoal(text: string): string {
  return HACKAPROMPT_GOAL.reduce((t, re) => t.replace(re, ' '), text);
}

/** Why a candidate regex would fail the RE2 portability gate, or null. */
export function re2Problem(regex: string): string | null {
  const findings = re2Findings(regex);
  if (findings.length > 0) return `not RE2 portable (${findings.map((f) => `${f.cls} ${f.token}`).join(', ')})`;
  const escapes = unportableEscapes(regex);
  return escapes.length > 0 ? `not RE2 portable (${escapes.join(', ')})` : null;
}

/** Why the corpus visibility gate would call the candidate unmeasured, or null. */
export function visibilityProblem(regex: string, corpus: GateCorpus): string | null {
  const visibility = fallbackVisibility(regex, corpus);
  return visibility < VISIBILITY_FLOOR
    ? `corpus visibility ${visibility} < ${VISIBILITY_FLOOR}: its zero benign FP measured almost nothing`
    : null;
}

/**
 * A category the schema knows. The model names it, and it becomes a directory
 * under rules/ and picks the reference defaults, so anything else is refused.
 */
export function isRuleCategory(category: string): category is ATRCategory {
  return Object.prototype.hasOwnProperty.call(DEFAULT_OWASP_LLM_BY_CATEGORY, category);
}

type Doc = Readonly<Record<string, unknown>>;

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((e): e is string => typeof e === 'string') : []);

/**
 * The authored rule as the PR's checks require it, whatever the model wrote:
 * status experimental (draft is never evaluated; maturity test keeps it in the
 * alert lane), no wild_fp_rate (this lane measures nothing in the wild), and
 * OWASP references as bare allowlisted ids, with the category default when
 * none survive. Returns a new object.
 */
export function finalizeAuthoredRule(doc: Doc, category: ATRCategory, allowlists: OwaspAllowlists): Record<string, unknown> {
  const { wild_fp_rate: _unmeasured, ...rest } = doc;
  const references = (doc.references && typeof doc.references === 'object' ? doc.references : {}) as Doc;
  const owasp = normalizeReferences(
    { category, owaspLlm: strings(references.owasp_llm), owaspAgentic: strings(references.owasp_agentic) },
    allowlists,
  );
  return { ...rest, status: 'experimental', references: { ...references, ...owasp } };
}
