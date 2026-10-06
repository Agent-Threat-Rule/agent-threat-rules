/**
 * Rule-corpus scan and visibility arithmetic for gate-corpus-visibility.ts.
 *
 * Kept separate from the gate so the measurement is unit-testable without a
 * corpus, a baseline, or a filesystem: everything below either reads one YAML
 * file or is a pure function of (rule, literal frequencies).
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { load as yamlLoad } from "js-yaml";
import {
  requirementOf,
  UNCONSTRAINED,
  type LiteralRequirement,
} from "./regex-literals.js";
import { isMeasurableField, unmeasurableReason } from "./corpus-event.js";

/**
 * Below this many candidate benign samples, a 0-false-positive result does not
 * bound anything useful.
 *
 * Rule of three: with V independent candidate samples and zero observed
 * failures, the 95% upper confidence bound on the failure rate is ~3/V. At the
 * floor that is a 30% ceiling on the FP rate among matchable inputs -- still
 * bad, deliberately. It is set where an author can actually reach it (ten
 * plausible legitimate uses of your own tokens is an afternoon, thirty is a
 * project), not where the evidence would be comfortable. The five rules this
 * gate was built from scored 0, 0, 0, 0 and 2.
 */
export const VISIBILITY_FLOOR = 10;

export type VisibilityTier = "blind" | "thin" | "measured";

export function tierOf(visibility: number): VisibilityTier {
  if (visibility <= 0) return "blind";
  return visibility < VISIBILITY_FLOOR ? "thin" : "measured";
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

export interface ParsedCondition {
  readonly field: string;
  readonly operator: string;
  /** The raw detection value, kept so --verify-blind can execute the real thing. */
  readonly value: string;
  readonly requirement: LiteralRequirement;
  /** Why this condition can never be exercised by a text corpus, if it cannot. */
  readonly note: string | null;
}

export interface ParsedRule {
  readonly id: string;
  /** Repo-relative path. */
  readonly file: string;
  readonly status: string;
  readonly maturity: string;
  readonly severity: string;
  /** detection.condition: "any" (default) or "all". */
  readonly combinator: string;
  readonly conditions: readonly ParsedCondition[];
}

/** A file under rules/ whose visibility could not be established. Never a pass. */
export interface UnreadableRule {
  readonly file: string;
  readonly reason: string;
}

export interface RuleCorpusScan {
  readonly rules: readonly ParsedRule[];
  readonly unreadable: readonly UnreadableRule[];
}

/** Every *.yaml/*.yml under a directory tree, sorted for deterministic reports. */
export function listRuleFiles(dir: string): readonly string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    let s;
    try {
      s = statSync(p);
    } catch {
      continue;
    }
    if (s.isDirectory()) out.push(...listRuleFiles(p));
    else if (s.isFile() && (entry.endsWith(".yaml") || entry.endsWith(".yml"))) out.push(p);
  }
  return out.sort();
}

/**
 * The literals a single condition requires.
 *
 * `regex` is the only operator in the corpus today. The substring operators are
 * handled because they are cheap and unambiguous; anything else returns
 * UNCONSTRAINED, so an operator this function has never heard of is reported as
 * visible rather than silently proved blind.
 */
export function conditionRequirement(
  operator: string,
  value: unknown,
): LiteralRequirement {
  if (typeof value !== "string" || value.length === 0) return UNCONSTRAINED;
  if (operator === "regex") return requirementOf(value);
  if (operator === "contains" || operator === "equals" || operator === "starts_with") {
    return { alternatives: [[value.toLowerCase()]], constrained: true };
  }
  return UNCONSTRAINED;
}

function parseCondition(raw: unknown): ParsedCondition | null {
  if (raw === null || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  const field = typeof c.field === "string" ? c.field : "";
  const operator = typeof c.operator === "string" ? c.operator : "";
  if (field === "" || operator === "") return null;
  const measurable = isMeasurableField(field);
  return {
    field,
    operator,
    value: typeof c.value === "string" ? c.value : "",
    requirement: measurable ? conditionRequirement(operator, c.value) : UNCONSTRAINED,
    note: measurable ? null : unmeasurableReason(field),
  };
}

export function readRule(absPath: string, repoRoot: string): ParsedRule | UnreadableRule {
  const file = relative(repoRoot, absPath);
  let doc: Record<string, unknown>;
  try {
    doc = yamlLoad(readFileSync(absPath, "utf-8")) as Record<string, unknown>;
  } catch (err) {
    return { file, reason: `YAML parse failed: ${(err as Error).message}` };
  }
  if (doc === null || typeof doc !== "object") return { file, reason: "not a YAML mapping" };
  const id = typeof doc.id === "string" ? doc.id : "";
  if (id === "") return { file, reason: "no `id:` field" };
  const detection = doc.detection as Record<string, unknown> | undefined;
  const rawConditions = detection?.conditions;
  if (!Array.isArray(rawConditions) || rawConditions.length === 0) {
    return { file, reason: `no detection.conditions (${id})` };
  }
  const conditions: ParsedCondition[] = [];
  for (const raw of rawConditions) {
    const parsed = parseCondition(raw);
    if (parsed === null) {
      return { file, reason: `detection.conditions entry has no field/operator (${id})` };
    }
    conditions.push(parsed);
  }
  return {
    id,
    file,
    status: typeof doc.status === "string" ? doc.status : "",
    maturity: typeof doc.maturity === "string" ? doc.maturity : "",
    severity: typeof doc.severity === "string" ? doc.severity : "",
    combinator: typeof detection?.condition === "string" ? detection.condition : "any",
    conditions,
  };
}

export function scanRuleCorpus(rulesDir: string, repoRoot: string): RuleCorpusScan {
  const rules: ParsedRule[] = [];
  const unreadable: UnreadableRule[] = [];
  for (const abs of listRuleFiles(rulesDir)) {
    const r = readRule(abs, repoRoot);
    if ("id" in r) rules.push(r);
    else unreadable.push(r);
  }
  return { rules, unreadable };
}

// ---------------------------------------------------------------------------
// Visibility
// ---------------------------------------------------------------------------

export interface MeasuredCondition extends ParsedCondition {
  readonly visibility: number;
}

export interface RuleVisibility {
  readonly id: string;
  readonly file: string;
  readonly status: string;
  readonly maturity: string;
  readonly severity: string;
  readonly combinator: string;
  readonly conditions: readonly MeasuredCondition[];
  /** The binding number: visibility of the LEAST visible condition. */
  readonly visibility: number;
  /** The most visible condition. Context only -- never the gate's verdict. */
  readonly widest: number;
  readonly blindConditions: number;
  readonly tier: VisibilityTier;
}

/**
 * How many benign samples could satisfy this condition's literal requirement.
 *
 * A conjunction is bounded by its rarest literal; the alternatives are ORed, so
 * the best of them bounds the condition. An UNCONSTRAINED requirement means the
 * extractor proved nothing, so the answer is the whole corpus -- "could match
 * anything" is the only honest reading of "I could not tell".
 */
export function conditionVisibility(
  requirement: LiteralRequirement,
  frequencies: ReadonlyMap<string, number>,
  sampleCount: number,
): number {
  if (!requirement.constrained) return sampleCount;
  let best = 0;
  for (const term of requirement.alternatives) {
    if (term.length === 0) return sampleCount;
    let bound = Number.POSITIVE_INFINITY;
    for (const lit of term) bound = Math.min(bound, frequencies.get(lit) ?? 0);
    best = Math.max(best, bound);
  }
  return Math.min(best, sampleCount);
}

/**
 * Rule visibility = the LEAST visible condition. Both combinators, no exception.
 *
 * This is the single load-bearing decision in the gate, and the first version
 * got it wrong. Taking the max for `condition: any` -- "the rule can fire, so it
 * was exposed" -- reproduced the exact bug the gate exists to catch. The Tor
 * rule that a reviewer later measured at 20% FP scored visibility 1786 and
 * sailed through, because one broad condition drowned out the torsocks
 * condition sitting at 1:
 *
 *     condition 1  requires "torsocks" AND one of curl/wget/nc/...   -> 1
 *     condition 4  (a much broader shape)                            -> 1786
 *     max = 1786 "measured"      min = 1 "thin"
 *
 * `any` means every condition is an independent way for the rule to fire. A 0
 * FP result is a claim about ALL of those paths, and it is only as strong as
 * the path the corpus tested least. A condition no benign sample can reach
 * contributes no evidence, and it is the untested path that a hand-written
 * benign sample walks straight into.
 *
 * For `all` the min is the obvious reading anyway: one unreachable conjunct
 * makes the whole rule unreachable.
 */
export function measureVisibility(
  rule: ParsedRule,
  frequencies: ReadonlyMap<string, number>,
  sampleCount: number,
): RuleVisibility {
  const conditions = rule.conditions.map((c) => ({
    ...c,
    visibility:
      c.note !== null
        ? 0
        : conditionVisibility(c.requirement, frequencies, sampleCount),
  }));
  const values = conditions.map((c) => c.visibility);
  const visibility = Math.min(...values);
  const widest = Math.max(...values);
  return {
    ...rule,
    conditions,
    visibility,
    widest,
    blindConditions: values.filter((v) => v <= 0).length,
    tier: tierOf(visibility),
  };
}
