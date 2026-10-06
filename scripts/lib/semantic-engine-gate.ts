/**
 * Engine-level gate for semantic (T2) drafts: measure the BUILT rule the way
 * check-rules-safety measures the PR this lane opens.
 *
 * WHY THIS EXISTS
 *   semantic-gate.ts tests the fallback regex against raw text. check-rules-safety
 *   pushes every sample through the engine with matchedRuleIds
 *   (src/corpus-event.ts): four event shapes plus scanSkill. On the
 *   post-tool-json shape (a tool_response event) the engine resolves an llm_io
 *   rule's user_input to the JSON-encoded content, where every newline, tab and
 *   CR is "\" + a letter. A fallback anchored on backslashes, or one that spans
 *   lines with .{0,N}, fires there and nowhere in the raw text: eleven blank
 *   lines were enough. check-rules-safety also charges a new rule against the
 *   research-mention corpus (check 4) and every other rule's true_negatives,
 *   peers in the same PR included (check 5). The lane measured none of that, so
 *   such a draft was caught only by the pre-push backstop, which fails the whole
 *   job and discards every other rule authored in the run. Measured here, the
 *   one draft is routed to human review and the run continues.
 *
 * SAME CODE, NOT A MIRROR
 *   The engine, matchedRuleIds and the draft/test activation below are the ones
 *   check-rules-safety uses, and so is its loose-regex lint (check 6). The
 *   rule is measured as its YAML file loads.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import yaml from "js-yaml";
import { ATREngine } from "../../src/engine.js";
import type { ATRRule } from "../../src/types.js";
import { lintRuleDoc } from "../lint-rule-patterns.js";
import { matchedRuleIds } from "./corpus-event.js";
import type { OwaspAllowlists } from "./normalize-references.js";
import type { ClusterCandidate } from "./semantic-clusters.js";
import { prepareGateCorpus, validateSemanticDraft, type GateResult, type SemanticDraft } from "./semantic-gate.js";
import { RULE_YAML_OPTIONS, buildSemanticRule } from "./semantic-rule-builder.js";

/** The id a draft's rule carries while it is measured. Real ids are allocated only after a pass. */
export const CANDIDATE_RULE_ID = "ATR-SEMANTIC-CANDIDATE";

/** check-rules-safety check 4 reads this file (RESEARCH_MENTIONS_FILE there). */
export const RESEARCH_MENTIONS_CORPUS = "data/research-mentions/corpus.jsonl";

export interface OwnedSample {
  readonly ownerId: string;
  readonly text: string;
}

/** What check-rules-safety charges a new rule against beyond MEASUREMENT_CORPORA. */
export interface ForeignRules {
  /** Research-mention texts: about attacks, not attacks (check 4). */
  readonly mentions: readonly string[];
  /** Every other rule's true_negatives, rules promoted earlier this run included (check 5). */
  readonly ruleTrueNegatives: readonly OwnedSample[];
  /** Rules promoted earlier this run. Check 5 also makes them offenders against a later rule's TNs. */
  readonly peers: readonly Record<string, unknown>[];
}

export interface DraftCheckInput {
  readonly draft: SemanticDraft;
  readonly candidate: ClusterCandidate;
  readonly allowlists: OwaspAllowlists;
  /** MEASUREMENT_CORPORA samples (check-rules-safety checks 3, 3b and 3c read the same directories). */
  readonly benignSamples: readonly string[];
  readonly foreign: ForeignRules;
}

export interface DraftCheckResult {
  readonly gate: GateResult;
  /** The built rule under CANDIDATE_RULE_ID, exactly as its YAML file loads. Set only on a pass. */
  readonly rule?: Record<string, unknown>;
}

const fail = (reason: string): GateResult => ({ ok: false, reason });
const snippet = (text: string): string => text.slice(0, 60).replace(/\s+/g, " ");

/** test_cases.<key> inputs, string or {input}: how check-rules-safety reads them. */
export function declaredInputs(rule: Record<string, unknown>, key: "true_positives" | "true_negatives"): string[] {
  const testCases = rule.test_cases as Record<string, unknown> | undefined;
  const list = Array.isArray(testCases?.[key]) ? (testCases[key] as unknown[]) : [];
  return list
    .map((t) => (typeof t === "string" ? t : (t as { input?: unknown } | null)?.input))
    .filter((t): t is string => typeof t === "string" && t.length > 0);
}

/**
 * An engine holding exactly these rules, draft/test activated the way
 * check-rules-safety activates them (engine.evaluate() skips draft). No
 * loadRules(): with no rulesDir it would load the bundled rule tree too.
 */
export function scopedEngine(rules: readonly Record<string, unknown>[]): ATREngine {
  const engine = new ATREngine();
  for (const rule of rules) {
    const inert = rule.status === "draft" || rule.status === "test";
    engine.addRule((inert ? { ...rule, status: "active" } : rule) as unknown as ATRRule);
  }
  return engine;
}

const fires = (engine: ATREngine, ruleId: string, text: string): boolean => matchedRuleIds(engine, text).has(ruleId);

/**
 * check-rules-safety check 6 on the built rule: no risky short keyword without
 * a \b (the 'nc' -> async false-positive class). Same lint function. A bare
 * keyword can be clean on every corpus the lane reads and still fail the PR.
 */
export function checkLooseRegex(rule: Record<string, unknown>): GateResult | null {
  const bare = lintRuleDoc(rule).find((f) => f.code === "bareword");
  return bare ? fail(`loose-regex lint (check-rules-safety check 6): ${bare.detail}`) : null;
}

/** check-rules-safety check 2 (every declared TP fires), plus none of the rule's own TNs fire. */
export function checkOwnTestCases(engine: ATREngine, rule: Record<string, unknown>): GateResult | null {
  const id = String(rule.id);
  const missed = declaredInputs(rule, "true_positives").find((t) => !fires(engine, id, t));
  if (missed !== undefined) return fail(`own true_positive not matched under the engine: "${snippet(missed)}"`);
  const hit = declaredInputs(rule, "true_negatives").find((t) => fires(engine, id, t));
  if (hit !== undefined) return fail(`own true_negative matched under the engine: "${snippet(hit)}"`);
  return null;
}

/** check-rules-safety checks 3/3b/3c, 4 and 5 (this rule as the offender). */
function checkCorpora(
  engine: ATREngine,
  id: string,
  benign: readonly string[],
  foreign: ForeignRules,
): GateResult | null {
  const fp = benign.find((t) => fires(engine, id, t));
  if (fp !== undefined) {
    return fail(`benign FP under the engine's event shapes (check-rules-safety checks 3/3b/3c): "${snippet(fp)}"`);
  }
  const mention = foreign.mentions.find((t) => fires(engine, id, t));
  if (mention !== undefined) return fail(`research-mention FP (check-rules-safety check 4): "${snippet(mention)}"`);
  const tn = foreign.ruleTrueNegatives.find((s) => s.ownerId !== id && fires(engine, id, s.text));
  if (tn !== undefined) {
    return fail(`cross-rule conflict (check-rules-safety check 5): fires on ${tn.ownerId}'s true_negative "${snippet(tn.text)}"`);
  }
  return null;
}

/** check-rules-safety check 5 the other way round: a peer promoted earlier this run as the offender. */
function checkPeers(rule: Record<string, unknown>, peers: readonly Record<string, unknown>[]): GateResult | null {
  if (peers.length === 0) return null;
  const engine = scopedEngine(peers);
  const ownId = String(rule.id);
  for (const text of declaredInputs(rule, "true_negatives")) {
    const offender = [...matchedRuleIds(engine, text)].find((id) => id !== ownId);
    if (offender !== undefined) {
      return fail(
        `cross-rule conflict (check-rules-safety check 5): ${offender}, promoted earlier this run, ` +
          `fires on this rule's true_negative "${snippet(text)}"`,
      );
    }
  }
  return null;
}

/** The rule as its YAML file loads: what check-rules-safety's engine will read. */
function asLoaded(rule: Record<string, unknown>): Record<string, unknown> {
  return yaml.load(yaml.dump(rule, RULE_YAML_OPTIONS)) as Record<string, unknown>;
}

/**
 * The whole deterministic gate for one draft: the regex-level checks in
 * semantic-gate.ts, then the built rule through the engine. Runs the draft's
 * regex, so call it through semantic-gate-runner.ts, which bounds its time.
 */
export function checkDraft(input: DraftCheckInput): DraftCheckResult {
  const { draft, candidate: c } = input;
  const gate = validateSemanticDraft(draft, c.truePositives, c.trueNegatives, prepareGateCorpus(input.benignSamples));
  if (!gate.ok) return { gate };
  const rule = asLoaded(buildSemanticRule(c, draft, CANDIDATE_RULE_ID, input.allowlists));
  const engine = scopedEngine([rule]);
  const failure =
    checkLooseRegex(rule) ??
    checkOwnTestCases(engine, rule) ??
    checkCorpora(engine, CANDIDATE_RULE_ID, input.benignSamples, input.foreign) ??
    checkPeers(rule, input.foreign.peers);
  return failure ? { gate: failure } : { gate, rule };
}

/** New foreign rules that also carry a just-promoted rule and its declared true_negatives. */
export function addPeer(foreign: ForeignRules, rule: Record<string, unknown>): ForeignRules {
  const ownerId = String(rule.id);
  return {
    ...foreign,
    ruleTrueNegatives: [
      ...foreign.ruleTrueNegatives,
      ...declaredInputs(rule, "true_negatives").map((text) => ({ ownerId, text })),
    ],
    peers: [...foreign.peers, rule],
  };
}

function ruleFiles(dir: string): string[] {
  return readdirSync(dir)
    .sort()
    .flatMap((entry) => {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) return ruleFiles(full);
      return entry.endsWith(".yaml") || entry.endsWith(".yml") ? [full] : [];
    });
}

type LoadedTns = { readonly samples: readonly OwnedSample[]; readonly error?: string };

function ruleTrueNegatives(rulesDir: string, file: string): LoadedTns {
  let doc: unknown;
  try {
    doc = yaml.load(readFileSync(file, "utf-8"));
  } catch (e) {
    return { samples: [], error: `cannot load ${relative(rulesDir, file)}: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (!doc || typeof doc !== "object") return { samples: [] };
  const rule = doc as Record<string, unknown>;
  const ownerId = typeof rule.id === "string" ? rule.id : relative(rulesDir, file);
  return { samples: declaredInputs(rule, "true_negatives").map((text) => ({ ownerId, text })) };
}

/**
 * Every rule's true_negatives under rulesDir, tagged with the owning id: the
 * set check-rules-safety's check 5 reads. A rule that does not parse is
 * reported, not skipped in silence; it would clear a draft of a conflict
 * nobody looked for.
 */
export function loadRuleTrueNegatives(rulesDir: string): { readonly samples: OwnedSample[]; readonly errors: string[] } {
  const loaded = ruleFiles(rulesDir).map((file) => ruleTrueNegatives(rulesDir, file));
  return {
    samples: loaded.flatMap((l) => l.samples),
    errors: loaded.flatMap((l) => (l.error ? [l.error] : [])),
  };
}
