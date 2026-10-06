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
import { earnedActions } from './semantic-rule-builder.js';
import type { ATRCategory } from '../../src/types.js';

/**
 * HackAPrompt's goal sentence, its spellings and the Spanish level's "He sido".
 * Removed before a candidate's recoveries are counted, so only what a regex
 * catches without it counts. PWNED goes first and the whole set repeats until
 * nothing changes: in "IhavebeenPWNED" there is no word boundary after "been"
 * until PWNED is gone.
 */
const HACKAPROMPT_GOAL = [
  /P[\W_]*W[\W_]*N[\W_]*(?:E|3|€)[\W_]*D/gi,
  /\bI\s*(?:have|'\s*ve)\s*been\b/gi,
  /\bhe\s*sido\b/gi,
];

export function withoutHackapromptGoal(text: string): string {
  const once = HACKAPROMPT_GOAL.reduce((t, re) => t.replace(re, ' '), text);
  return once === text ? text : withoutHackapromptGoal(once);
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

/** The maturity this lane writes: alert lane, never enforce. */
export const AUTHORED_MATURITY = 'test';

/**
 * response with only the actions the maturity has earned (action-eligibility:
 * a test rule with no FP measurement is capped at observe, so block_input,
 * copied from the reference rule, goes). A message that announced a block it
 * no longer makes is replaced.
 */
function earnedResponse(doc: Doc): Doc | undefined {
  const response = doc.response && typeof doc.response === 'object' ? (doc.response as Doc) : undefined;
  if (!response) return undefined;
  const declared = strings(response.actions);
  const actions = earnedActions(declared, AUTHORED_MATURITY);
  if (actions.length === declared.length && actions.every((a, i) => a === declared[i])) return response;
  const message = typeof response.message_template === 'string' && !/\bblock/i.test(response.message_template)
    ? response.message_template
    : `[${String(doc.id)}] ${String(doc.title)} detected.`;
  return { ...response, actions, message_template: message };
}

/**
 * The authored rule as the PR's checks require it, whatever the model wrote:
 * status experimental (draft is never evaluated) at maturity test (alert lane,
 * never enforce), response actions the maturity has earned, no wild_fp_rate
 * (this lane measures nothing in the wild), and OWASP references as bare
 * allowlisted ids, with the category default when none survive. Returns a new
 * object.
 */
export function finalizeAuthoredRule(doc: Doc, category: ATRCategory, allowlists: OwaspAllowlists): Record<string, unknown> {
  const { wild_fp_rate: _unmeasured, ...rest } = doc;
  const references = (doc.references && typeof doc.references === 'object' ? doc.references : {}) as Doc;
  const owasp = normalizeReferences(
    { category, owaspLlm: strings(references.owasp_llm), owaspAgentic: strings(references.owasp_agentic) },
    allowlists,
  );
  const response = earnedResponse(doc);
  return {
    ...rest,
    status: 'experimental',
    maturity: AUTHORED_MATURITY,
    references: { ...references, ...owasp },
    ...(response ? { response } : {}),
  };
}
