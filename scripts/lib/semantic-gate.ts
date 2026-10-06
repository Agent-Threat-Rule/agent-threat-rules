/**
 * Deterministic gate for semantic (T2) rule drafts -- the part that does NOT
 * trust the LLM.
 *
 * WHY IT MEASURES THE WAY CI DOES
 *   Rolling PR #632 (eight rules) cleared this lane's gate and then failed four
 *   CI checks, because the lane measured its fallback regex differently from
 *   the checks that judged the PR:
 *     - it required ONE true positive to fire, while the rule declared up to
 *       eight and rule-quality / check-rules-safety require every one to fire;
 *     - it compiled with the literal inline flags, while src/engine.ts always
 *       compiles case-insensitive, drops ReDoS-shaped patterns and tests the
 *       unicode-normalised field before the raw one;
 *     - it scored FPs on a small sample instead of MEASUREMENT_CORPORA;
 *     - it never asked whether the pattern is RE2 portable, or whether the
 *       benign corpus contains the literals the pattern needs at all.
 *   Each helper below closes one of those gaps with the same code or the same
 *   arithmetic the CI gate uses.
 *
 * WHAT THIS FILE DOES NOT MEASURE
 *   It tests the fallback against raw text only. check-rules-safety pushes every
 *   sample through the engine on four event shapes (src/corpus-event.ts); on the
 *   JSON-encoded tool_response shape an llm_io rule reads the encoded content,
 *   where a newline is "\" + "n". It also charges a new rule against the
 *   research-mention corpus and every other rule's true_negatives. Passing here
 *   is necessary, not sufficient: scripts/lib/semantic-engine-gate.ts runs that
 *   measurement on the built rule, with check-rules-safety's own code.
 */
import { foldConfusables, isReDoSSafe, needsUnicodeFlag, normalizeUnicode } from "../../src/engine.js";
import { scanPattern, type Finding } from "../audit-re2-portability.js";
import { buildLiteralIndex, documentFrequencies, frequencyMap } from "./literal-index.js";
import { literalsOf } from "./regex-literals.js";
import { VISIBILITY_FLOOR, conditionRequirement, conditionVisibility } from "./visibility-scan.js";

/** What the model PROPOSES. The gate decides if it ships. */
export interface SemanticDraft {
  insufficient?: boolean;
  reason?: string;
  // Narrow, generalized regex fallback (anchor + redirect), low-FP by design.
  fallback_regex?: string;
  fallback_description?: string;
  // The LLM-as-judge prompt body (must contain {{input}} and the untrusted guard).
  judge_prompt?: string;
  // A crisp one-line definition of the attack class for the rule description.
  attack_definition?: string;
  not_detected?: string;
  false_positive_scenarios?: string[];
  // Extra reworded TPs the judge should catch but the narrow regex may miss.
  paraphrase_tests?: string[];
}

export interface GateResult {
  readonly ok: boolean;
  readonly reason: string;
  /** Set on a pass: what the fallback was measured at, for the run report. */
  readonly metrics?: { readonly tp_hits: number; readonly tp_total: number; readonly visibility: number };
}

/**
 * A fallback must catch at least this many of the cluster's attack samples.
 * Fewer, and the regex is a keyword for one phrasing rather than a detector of
 * the class; the judge alone carries the rule and the fallback adds FP risk
 * without recall.
 */
export const MIN_FALLBACK_TP_HITS = 3;

/** Mirrors MAX_EVAL_LENGTH in src/engine.ts: the engine skips longer inputs. */
const ENGINE_MAX_EVAL_LENGTH = 100_000;

/** Mirrors normalizeRegex in src/engine.ts: only these inline flags are stripped. */
const ENGINE_INLINE_FLAGS = /^\(\?[imsx]+\)/;

const UNTRUSTED_GUARD =
  /(untrusted|never follow|do not follow|treat (everything|all|the content)|ignore any instructions)/i;

/** Convert an ATR pattern value (may carry leading inline (?i)) into a RegExp. */
export function toJsRegExp(value: string): RegExp {
  let flags = "";
  let src = value;
  const m = src.match(/^\(\?([a-z]+)\)/);
  if (m) {
    if (m[1].includes("i")) flags += "i";
    if (m[1].includes("m")) flags += "m";
    if (m[1].includes("s")) flags += "s";
    src = src.slice(m[0].length);
  }
  return new RegExp(src, flags);
}

export type CompileResult =
  | { readonly ok: true; readonly regex: RegExp }
  | { readonly ok: false; readonly reason: string };

/**
 * Compile a fallback exactly as src/engine.ts compiles an array-format regex
 * condition: strip a leading (?imsx) group, always `i`, `u` when the pattern
 * needs it, and refuse what the engine's ReDoS gate would silently drop.
 */
export function compileFallback(value: string): CompileResult {
  const source = value.replace(ENGINE_INLINE_FLAGS, "");
  if (!isReDoSSafe(source)) {
    return { ok: false, reason: `fallback_regex is ReDoS-shaped; the engine refuses to compile it: ${value}` };
  }
  try {
    return { ok: true, regex: new RegExp(source, needsUnicodeFlag(source) ? "iu" : "i") };
  } catch (e) {
    return { ok: false, reason: `fallback_regex does not compile (${value}): ${e}` };
  }
}

/** Engine field semantics: test the normalised text, then the raw text if they differ. */
export function fallbackMatches(rx: RegExp, text: string): boolean {
  const normalised = foldConfusables(normalizeUnicode(text));
  if (rx.test(normalised)) return true;
  return normalised !== text && rx.test(text);
}

/**
 * Partition cluster TPs into those the fallback catches (declared as
 * test_cases.true_positives) and those only the judge can catch. Inputs are
 * trimmed and de-duplicated first, because the rule stores trimmed inputs.
 *
 * Each input is evaluated exactly once. The fallback is untrusted LLM output,
 * and the TPs it misses are where a backtracking pattern does its worst work.
 */
export function splitTruePositives(
  rx: RegExp,
  truePositives: readonly string[],
): { readonly hits: string[]; readonly misses: string[] } {
  const inputs = [...new Set(truePositives.map((t) => (typeof t === "string" ? t.trim() : "")))].filter(
    (t) => t.length > 0,
  );
  const verdicts = inputs.map((t) => ({ t, hit: t.length <= ENGINE_MAX_EVAL_LENGTH && fallbackMatches(rx, t) }));
  return {
    hits: verdicts.filter((v) => v.hit).map((v) => v.t),
    misses: verdicts.filter((v) => !v.hit).map((v) => v.t),
  };
}

/** RE2 incompatibilities, from the same scanner the RE2 portability gate runs. */
export function re2Findings(value: string): readonly Finding[] {
  return scanPattern(value);
}

// ---------------------------------------------------------------------------
// Gate corpus: MEASUREMENT_CORPORA, prepared once and reused for every draft
// ---------------------------------------------------------------------------

export interface GateCorpus {
  /** Raw benign samples, as loadBenignSamples() returns them. */
  readonly samples: readonly string[];
  /** foldConfusables(normalizeUnicode(sample)): what the engine tests first. */
  readonly normalized: readonly string[];
  /** Lowercased raw samples: what the corpus visibility gate counts literals in. */
  readonly lowered: readonly string[];
}

export function prepareGateCorpus(samples: readonly string[]): GateCorpus {
  return {
    samples: [...samples],
    normalized: samples.map((s) => foldConfusables(normalizeUnicode(s))),
    lowered: samples.map((s) => s.toLowerCase()),
  };
}

/**
 * Index of the first benign sample the fallback fires on, or -1. Unlike the
 * engine, no input-length cap is applied: that can only over-report FPs.
 */
export function findBenignFp(rx: RegExp, corpus: GateCorpus): number {
  for (let i = 0; i < corpus.samples.length; i += 1) {
    const normalised = corpus.normalized[i]!;
    const raw = corpus.samples[i]!;
    if (rx.test(normalised) || (normalised !== raw && rx.test(raw))) return i;
  }
  return -1;
}

/**
 * How many benign samples could possibly match the fallback: the arithmetic of
 * scripts/gate-corpus-visibility.ts (required literals, document frequency on
 * the lowercased corpus) applied to one pattern.
 */
export function fallbackVisibility(value: string, corpus: GateCorpus): number {
  const requirement = conditionRequirement("regex", value);
  const total = corpus.lowered.length;
  if (!requirement.constrained) return total;
  const index = buildLiteralIndex(literalsOf(requirement));
  const frequencies = frequencyMap(index, documentFrequencies(index, corpus.lowered));
  return conditionVisibility(requirement, frequencies, total);
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

const fail = (reason: string): GateResult => ({ ok: false, reason });

function checkJudge(draft: SemanticDraft): GateResult | null {
  const jp = (draft.judge_prompt ?? "").trim();
  if (jp.length < 80) return fail("judge_prompt too short / missing");
  if (!jp.includes("{{input}}")) return fail("judge_prompt missing {{input}} placeholder");
  if (!UNTRUSTED_GUARD.test(jp)) {
    return fail("judge_prompt missing untrusted-data guard (prompt-injection self-defense)");
  }
  if (!draft.attack_definition || draft.attack_definition.trim().length < 12) {
    return fail("missing attack_definition");
  }
  return null;
}

function checkFallbackShape(raw: string): GateResult | null {
  if (raw.length < 8) return fail("fallback_regex too short / missing");
  // Specificity floor: reject a bare single common token with no structure.
  const bare = raw.replace(/^\(\?[a-z]+\)/, "");
  if (/^[\w-]{1,12}$/.test(bare) && !/[.\\[\](){}|^$*+?]/.test(bare)) {
    return fail(`fallback_regex too generic: ${raw}`);
  }
  return null;
}

function checkRe2(raw: string): GateResult | null {
  const findings = re2Findings(raw);
  if (findings.length === 0) return null;
  const what = findings.map((f) => `${f.cls} ${f.token}`).join(", ");
  return fail(`fallback_regex is not RE2 portable (${what}); downstream RE2 engines reject it`);
}

function checkTruePositiveHits(split: { readonly hits: string[]; readonly misses: string[] }): GateResult | null {
  const { hits, misses } = split;
  const total = hits.length + misses.length;
  if (total < MIN_FALLBACK_TP_HITS) return fail(`need >=${MIN_FALLBACK_TP_HITS} true_positives, cluster has ${total}`);
  if (hits.length < MIN_FALLBACK_TP_HITS) {
    return fail(
      `fallback_regex matches ${hits.length} of ${total} true_positives (need >=${MIN_FALLBACK_TP_HITS}; ` +
        "a fallback that misses the class is a keyword, not a detector)",
    );
  }
  return null;
}

function checkNoFalsePositives(rx: RegExp, trueNegatives: readonly string[], corpus: GateCorpus): GateResult | null {
  const fp = findBenignFp(rx, corpus);
  if (fp >= 0) {
    return fail(`benign FP: /${rx.source}/ matches benign "${corpus.samples[fp]!.slice(0, 60)}"`);
  }
  const tn = trueNegatives.map((t) => t.trim()).find((t) => t.length > 0 && fallbackMatches(rx, t));
  if (tn !== undefined) return fail(`FP on own true_negative: /${rx.source}/ matches "${tn.slice(0, 60)}"`);
  return null;
}

/**
 * Verify a semantic draft deterministically. Returns ok:false (route to human)
 * for anything unsafe to auto-promote.
 *
 * @param draft         the model's proposal
 * @param truePositives the cluster's attack samples (fallback must catch >= 3)
 * @param trueNegatives the cluster's benign samples (fallback must catch 0)
 * @param corpus        the gate corpus (fallback must catch 0, and must be visible to it)
 */
export function validateSemanticDraft(
  draft: SemanticDraft,
  truePositives: readonly string[],
  trueNegatives: readonly string[],
  corpus: GateCorpus,
): GateResult {
  if (draft.insufficient) return fail(`llm-insufficient: ${draft.reason ?? "no reason given"}`);
  const judge = checkJudge(draft);
  if (judge) return judge;

  const raw = (draft.fallback_regex ?? "").trim();
  const shape = checkFallbackShape(raw);
  if (shape) return shape;
  const compiled = compileFallback(raw);
  if (!compiled.ok) return fail(compiled.reason);
  const re2 = checkRe2(raw);
  if (re2) return re2;

  const split = splitTruePositives(compiled.regex, truePositives);
  const hits = checkTruePositiveHits(split);
  if (hits) return hits;
  const fps = checkNoFalsePositives(compiled.regex, trueNegatives, corpus);
  if (fps) return fps;

  const visibility = fallbackVisibility(raw, corpus);
  if (visibility < VISIBILITY_FLOOR) {
    return fail(
      `fallback visibility ${visibility} < ${VISIBILITY_FLOOR}: only ${visibility} of ${corpus.samples.length} benign ` +
        "samples contain the literals it requires, so its 0 FP measured almost nothing (corpus visibility gate)",
    );
  }
  return {
    ok: true,
    reason: "passed",
    metrics: { tp_hits: split.hits.length, tp_total: split.hits.length + split.misses.length, visibility },
  };
}
