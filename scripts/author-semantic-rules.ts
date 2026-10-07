#!/usr/bin/env npx tsx
/**
 * author-semantic-rules.ts
 *
 * Daily authoring of method=semantic (T2) ATR rules from semantic-attack
 * adversarial samples (PromptInject / HackAPrompt clusters; garak is
 * quarantined, see QUARANTINED SOURCES below).
 *
 * WHY SEMANTIC, NOT REGEX
 * -----------------------
 * Pure regex on a semantic attack (prompt injection / jailbreak) is the
 * MiroFish failure mode: it ends up keying on the wording that *describes*
 * the attack, fires on benign paraphrases, and is bypassed by the next
 * rewording. The right shape for this attack class is the validated T2
 * architecture demonstrated by ATR-2026-00573:
 *
 *   detection.method: semantic
 *   detection.conditions:  NARROW regex fallback (anchor + redirect) used only
 *                          when no judge is configured — built to be low-FP, not
 *                          high-recall.
 *   detection.semantic:    a high-quality LLM-as-judge prompt that DEFINES the
 *                          attack class with explicit positive AND negative
 *                          examples, scores 0..1, and returns strict JSON.
 *
 * The judge carries recall against reworded variants; the narrow regex carries
 * graceful degradation. The judge prompt's quality is what makes the whole rule
 * effective, so the model authors it here — but a deterministic gate (which the
 * model cannot bypass) decides whether the rule ships.
 *
 * THE GATE (the part that does NOT trust the LLM)
 * -----------------------------------------------
 * It measures the fallback the way the CI checks on the PR will, because
 * rolling PR #632 passed a looser gate here and then failed four of them.
 * scripts/lib/semantic-gate.ts, on the regex:
 *  - The fallback MUST compile under the engine's semantics (always
 *    case-insensitive, ReDoS-shaped patterns refused) and be RE2 portable.
 *  - It MUST catch >= 3 of the cluster's true_positives. Only those hits are
 *    declared as test_cases.true_positives; the misses become judge-only
 *    evasion_tests, so CI's "every declared TP fires" holds by construction.
 *  - It MUST produce ZERO matches on the gate corpora (MEASUREMENT_CORPORA,
 *    the same samples gate-promotion-fp.ts and the visibility gate read) and
 *    on its own true_negatives.
 *  - It MUST be visible to that corpus (>= VISIBILITY_FLOOR samples contain
 *    its required literals), or its 0 FP measured nothing.
 *  - The judge prompt MUST contain the untrusted-data guard and the {{input}}
 *    placeholder (so we never ship a judge the attacker can hijack).
 * scripts/lib/semantic-engine-gate.ts, on the built rule, with
 * check-rules-safety's own engine and event shapes (the JSON-encoded
 * tool_response shape included):
 *  - every declared TP fires and no declared TN does;
 *  - zero matches on MEASUREMENT_CORPORA, on data/research-mentions, and on
 *    every other rule's true_negatives; a rule promoted earlier in this run
 *    must not fire on this one's true_negatives either.
 * Both run in a worker under a wall-clock budget (semantic-gate-runner.ts), so
 * a catastrophically backtracking fallback is stopped and routed instead of
 * hanging the run; a draft that passes then goes through scripts/gate-redos.py
 * alone (semantic-redos-precheck.ts), PR CI's ReDoS gate.
 * A draft failing any of these is routed to human review; it is never promoted
 * automatically, and it never takes the rest of the run down with it at the
 * workflow's pre-push backstop. references are normalised against the OWASP
 * allowlists and a template compliance block is added, both marked for human
 * review.
 *
 * SCOPE FILTER (keep ATR in its lane)
 * -----------------------------------
 * garak clusters mix agent-attack families (prompt injection / instruction
 * override / jailbreak / context extraction — IN scope) with content-safety
 * families (dra, lmrc — graphic violence / weapons / drug synthesis — NOT an
 * agent threat, OUT of scope). Content-safety clusters are skipped so ATR does
 * not grow a content-moderation surface it never claimed.
 *
 * ID ALLOCATION
 * -------------
 * Strict increment past every id already taken (scripts/lib/rule-ids.ts):
 * ids declared and named on disk, and ids in the names of rule files open PRs
 * touch (--open-pr-files). Disk alone is main plus this lane's rolling branch;
 * the fn-mine lane's open PR holds ids neither has, and allocating without them
 * collides when the second PR merges. IDs are allocated only AFTER a draft
 * passes the gate, so failures never burn an id.
 *
 * USAGE
 *   npx tsx scripts/author-semantic-rules.ts            # dry-run (uses whichever backend is configured)
 *   npx tsx scripts/author-semantic-rules.ts --write    # write rules
 *   ... --max 5                 cap promotions
 *   ... --source hackaprompt    only this cluster source (hackaprompt|promptinject|garak)
 *   ... --include-quarantined   also read quarantined sources (garak); supervised runs only
 *   ... --report /tmp/r.json    write a run-summary JSON (for the workflow)
 *   ... --exclude-from FILE     never author a cluster listed in FILE (one proposal
 *                               path per line). The workflow writes it with
 *                               scripts/semantic-authored-history.ts: every cluster
 *                               this lane has authored, including rules a closed PR
 *                               or a reviewer threw away.
 *   ... --open-pr-files FILE    paths the repository's open PRs touch, one per line
 *                               (the workflow writes it with `gh pr list`). New ids
 *                               skip every rule id named there. Required with --write.
 *   ... --base REF              the PR's base (the workflow passes origin/main). Rules
 *                               already new against it -- a resumed rolling branch's --
 *                               count against check-rules-safety's per-PR cap
 *                               (MAX_NEW_PER_PR, default 10) and are gated as peers
 *                               (check 5). Without it the run assumes a PR of its own.
 *
 * ENV
 *   CLAUDE_CODE_OAUTH_TOKEN  preferred — routes through the local `claude` CLI and spends
 *                       subscription credit. Mint with `claude setup-token`.
 *   ANTHROPIC_API_KEY   fallback — metered credit. One of the two is required
 *                       (else exit 2; no fabricated rules).
 *   ATR_AUTHOR_MODEL    model id (default claude-haiku-4-5-20251001; set a
 *                       Sonnet/Opus id in CI for best judge-prompt quality)
 *
 * EXIT CODES
 *   0 success (promoted 0 or more; any failures were content-level)
 *   1 fatal IO / parse error
 *   2 no API key / no source text
 *   4 the lane could not run — every attempted candidate died on an
 *     infrastructure error (credit, auth, rate limit, network). Distinct from
 *     0, because "promoted 0 because nothing qualified" and "promoted 0
 *     because the API was down" must not look the same to CI.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { callClaude as sharedCallClaude, describeBackend, backendAvailable } from "./lib/claude-client.js";
import { loadBenignSamples, loadCorpusTexts } from "./lib/benign-corpus.js";
import { loadOwaspAllowlists, type OwaspAllowlists } from "./lib/normalize-references.js";
import { buildAuthorPrompt, extractJson } from "./lib/semantic-author-prompt.js";
import { QUARANTINE_REASON, findCandidates, type ClusterCandidate, type Skip } from "./lib/semantic-clusters.js";
import {
  RESEARCH_MENTIONS_CORPUS,
  addPeer,
  loadRuleTrueNegatives,
  type DraftCheckResult,
  type ForeignRules,
} from "./lib/semantic-engine-gate.js";
import type { SemanticDraft } from "./lib/semantic-gate.js";
import { runDraftCheckWithBudget } from "./lib/semantic-gate-runner.js";
import { redosPrecheck } from "./lib/semantic-redos-precheck.js";
import { DEFAULT_AUTHOR_MODEL, RULE_YAML_OPTIONS } from "./lib/semantic-rule-builder.js";

// The lane is split across scripts/lib/semantic-*.ts: cluster discovery, the
// author prompt, the deterministic gate and rule construction. Re-exported so
// this script stays the single entry point its tests and callers import from.
export { toJsRegExp, validateSemanticDraft, type GateResult, type SemanticDraft } from "./lib/semantic-gate.js";
export { buildAuthorPrompt, extractJson } from "./lib/semantic-author-prompt.js";
export {
  findCandidates,
  isQuarantinedSource,
  type ClusterCandidate,
  type FindCandidatesOptions,
} from "./lib/semantic-clusters.js";
export { buildSemanticRule, earnedActions } from "./lib/semantic-rule-builder.js";
import { readExcludeList } from "./lib/semantic-exclusions.js";
import { getNewRuleFiles } from "./check-rules-safety.js";
import { formatRuleId, nextRuleSeq, readRuleFileIds, usedRuleSeqs } from "./lib/rule-ids.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const RULES_BASE = resolve(REPO_ROOT, "rules");
const DEFAULT_MODEL = DEFAULT_AUTHOR_MODEL;
const DEFAULT_MAX = 10;
// Floor below which the 0-FP gate is not trustworthy: an empty/tiny benign
// corpus (e.g. a fresh checkout where build-benign-corpus.ts never ran) would
// let the FP loop pass vacuously, defeating the whole safety property.
const MIN_BENIGN_CORPUS = 50;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};
const WRITE = flag("--write");
const SOURCE_FILTER = opt("--source");
const INCLUDE_QUARANTINED = flag("--include-quarantined");
const MAX_PROMOTE = opt("--max") ? parseInt(opt("--max")!, 10) : DEFAULT_MAX;
const REPORT_PATH = opt("--report");
const EXCLUDE_FROM = opt("--exclude-from");
const BASE_REF = opt("--base");
const OPEN_PR_FILES = opt("--open-pr-files");
const RULE_ID_YEAR = "2026";
const DRY_RUN = !WRITE;

/**
 * Clusters that already have a rule authored by this lane.
 *
 * Every rule written here records the proposal it came from in
 * `_semantic_authored.source_cluster`. Without reading that back, each run
 * starts from the top of the same candidate list and re-authors the same
 * clusters, and every run opens a PR that duplicates the previous one. The
 * workflow checks out the rolling branch merged with main before this runs, so
 * the rules tree holds both merged rules and rules still waiting for review.
 */
export function authoredClustersFromRules(docs: unknown[]): Set<string> {
  const seen = new Set<string>();
  for (const doc of docs) {
    if (!doc || typeof doc !== "object") continue;
    const meta = (doc as { _semantic_authored?: unknown })._semantic_authored;
    if (!meta || typeof meta !== "object") continue;
    const src = (meta as { source_cluster?: unknown }).source_cluster;
    if (typeof src === "string" && src.length > 0) seen.add(src);
  }
  return seen;
}

/** Split candidates into those still to author and those already authored. Order is kept. */
export function excludeAuthored<T extends { proposalRel: string }>(
  candidates: T[],
  authored: Set<string>,
): { fresh: T[]; alreadyAuthored: T[] } {
  const fresh: T[] = [];
  const alreadyAuthored: T[] = [];
  for (const c of candidates) (authored.has(c.proposalRel) ? alreadyAuthored : fresh).push(c);
  return { fresh, alreadyAuthored };
}

/**
 * Split the clusters found into the ones to author, the ones whose rule is in
 * the tree, and the ones authored before whose rule is gone (a rolling PR closed
 * without merging, a rule a reviewer deleted). The tree alone forgets the last
 * kind and hands those clusters straight back. Order is kept.
 */
export function selectCandidates<T extends { proposalRel: string }>(
  found: T[],
  inTree: Set<string>,
  authoredEver: Set<string>,
): { fresh: T[]; alreadyAuthored: T[]; authoredBefore: T[] } {
  const { fresh: notInTree, alreadyAuthored } = excludeAuthored(found, inTree);
  const { fresh, alreadyAuthored: authoredBefore } = excludeAuthored(notInTree, authoredEver);
  return { fresh, alreadyAuthored, authoredBefore };
}

function loadAuthoredClusters(): Set<string> {
  const docs: unknown[] = [];
  for (const f of walkYamlAll(RULES_BASE)) {
    try {
      docs.push(yaml.load(readFileSync(f, "utf-8")));
    } catch {
      /* a rule that does not parse is validate's problem, not this lane's */
    }
  }
  return authoredClustersFromRules(docs);
}

// ---------------------------------------------------------------------------
// The PR this run adds to: check-rules-safety's per-PR cap and its peers
// ---------------------------------------------------------------------------
/**
 * check-rules-safety fails a PR that adds more than MAX_NEW_PER_PR rule files
 * (default 10), and on a resumed rolling branch the rules earlier runs added
 * count too. Read with the same default and the same refusal of a value that
 * is not a positive integer.
 */
export function parsePerPrCap(raw: string | undefined): number {
  const cap = Number(raw ?? "10");
  if (!Number.isInteger(cap) || cap <= 0) throw new Error(`MAX_NEW_PER_PR must be a positive integer, got "${raw}"`);
  return cap;
}

/** How many candidates this run may take on without pushing the PR past the per-PR cap. */
export function promotionBudget(requested: number, alreadyInPr: number, perPrCap: number): number {
  return Math.max(0, Math.min(requested, perPrCap - alreadyInPr));
}

export interface PendingRules {
  readonly files: readonly string[];
  /** Each file as its YAML loads: the peers check-rules-safety's check 5 charges a new rule against. */
  readonly rules: readonly Record<string, unknown>[];
  readonly errors: readonly string[];
}

/**
 * The rules the PR already adds against `base`, found the way check-rules-safety
 * finds them (getNewRuleFiles: added since the merge base, plus untracked).
 */
export function loadPendingRules(
  base: string,
  repoRoot: string,
  listNew: (base: string, repoRoot: string, onError: (m: string) => void) => string[] = (b, r, e) =>
    getNewRuleFiles(b, r, undefined, e),
): PendingRules {
  const errors: string[] = [];
  const files = listNew(base, repoRoot, (m) => errors.push(m));
  const rules: Record<string, unknown>[] = [];
  for (const f of files) {
    try {
      const doc = yaml.load(readFileSync(join(repoRoot, f), "utf-8"));
      if (doc && typeof doc === "object" && !Array.isArray(doc)) rules.push(doc as Record<string, unknown>);
      else errors.push(`${f}: not a YAML mapping`);
    } catch (e) {
      errors.push(`${f}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { files, rules, errors };
}

const NO_PENDING: PendingRules = { files: [], rules: [], errors: [] };

// ---------------------------------------------------------------------------
// ID allocation — strict increment past every taken id (scripts/lib/rule-ids.ts)
// ---------------------------------------------------------------------------
/** Hands out ids above every taken sequence number, never one already handed out. */
export function atrIdAllocator(used: readonly number[], year: string = RULE_ID_YEAR): () => string {
  const taken = new Set(used);
  let next = nextRuleSeq(used);
  return () => {
    while (taken.has(next)) next += 1;
    taken.add(next);
    return formatRuleId(year, next);
  };
}

/** The paths open PRs touch, one per line. Unreadable is fatal: an empty list is how ids collide. */
export function readOpenPrFiles(path: string): readonly string[] {
  return readFileSync(path, "utf-8").split("\n").map((l) => l.trim()).filter(Boolean);
}

function nextAtrId(openPrFiles: readonly string[]): () => string {
  return atrIdAllocator(usedRuleSeqs(readRuleFileIds(REPO_ROOT, "rules"), openPrFiles, RULE_ID_YEAR));
}

function openPrFilesOrExit(): readonly string[] {
  if (!OPEN_PR_FILES) {
    if (WRITE) {
      console.error("FATAL: --write needs --open-pr-files: ids allocated without other open PRs' rules collide with them");
      process.exit(1);
    }
    return [];
  }
  try {
    return readOpenPrFiles(OPEN_PR_FILES);
  } catch (e) {
    console.error(`FATAL: cannot read --open-pr-files ${OPEN_PR_FILES}: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}

// Like walkYaml but for the rules tree (any .yaml/.yml, not just proposals).
function walkYamlAll(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const f = join(dir, entry);
    let s;
    try {
      s = statSync(f);
    } catch {
      continue;
    }
    if (s.isDirectory()) out.push(...walkYamlAll(f));
    else if (s.isFile() && (entry.endsWith(".yaml") || entry.endsWith(".yml"))) out.push(f);
  }
  return out;
}

function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

// ---------------------------------------------------------------------------
// LLM authoring (the thin network-bound part)
// ---------------------------------------------------------------------------
/**
 * Route through the shared client so this lane spends subscription credit via
 * the local `claude` CLI when a CLAUDE_CODE_OAUTH_TOKEN is present, and only
 * falls back to the metered API key when it is not. See scripts/lib/claude-client.ts:
 * a metered balance running out is what killed this lane silently on 2026-09-21.
 */
async function callLlm(prompt: string): Promise<SemanticDraft | null> {
  if (!backendAvailable()) return null;
  const model = process.env.ATR_AUTHOR_MODEL || DEFAULT_MODEL;
  const out = await sharedCallClaude("", prompt, model, 4096);
  return extractJson(out);
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------
function emit(o: Record<string, unknown>): void {
  console.error(JSON.stringify(o));
}

export interface AuthorContext {
  /** The model call. Injected so the orchestration can be tested without a network. */
  readonly requestDraft: (prompt: string) => Promise<SemanticDraft | null>;
  readonly idGen: () => string;
  /** MEASUREMENT_CORPORA samples, loaded once; the gate worker prepares its own view. */
  readonly benignSamples: readonly string[];
  readonly allowlists: OwaspAllowlists;
  /** Research mentions, other rules' TNs and this run's promotions: grows with each promotion. */
  readonly foreign: ForeignRules;
}

export type Outcome =
  | { readonly kind: "error"; readonly errorKind: "infrastructure" | "content"; readonly record: Record<string, unknown> }
  | { readonly kind: "routed"; readonly record: Record<string, unknown> }
  | { readonly kind: "promoted"; readonly record: Record<string, unknown> };

/** One candidate's outcome, and the context the next candidate is gated against. */
interface Step {
  readonly outcome: Outcome;
  readonly ctx: AuthorContext;
}

const routed = (cluster: string, reason: string): Outcome => ({
  kind: "routed",
  record: { cluster, status: "routed_to_human", reason },
});

/** The gate could not run at all: not a verdict on the draft, and counted toward lane-down. */
const gateDown = (cluster: string, reason: string): Outcome => ({
  kind: "error",
  errorKind: "infrastructure",
  record: { cluster, status: "error", error_kind: "infrastructure", reason },
});

function writeRule(c: ClusterCandidate, id: string, rule: Record<string, unknown>): string {
  const slug = slugify(c.title) || id.toLowerCase();
  const outDir = join(RULES_BASE, c.category);
  const outAbs = join(outDir, `${id}-semantic-${slug}.yaml`);
  if (WRITE) {
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(outAbs, yaml.dump(rule, RULE_YAML_OPTIONS), "utf-8");
  }
  return outAbs.slice(REPO_ROOT.length + 1);
}

type DraftOrOutcome = { readonly draft: SemanticDraft } | { readonly outcome: Outcome };

async function draftFor(c: ClusterCandidate, ctx: AuthorContext): Promise<DraftOrOutcome> {
  const cluster = c.proposalRel;
  try {
    const draft = await ctx.requestDraft(buildAuthorPrompt(c, ctx.benignSamples));
    return draft ? { draft } : { outcome: routed(cluster, "llm returned no JSON") };
  } catch (e) {
    const reason = String(e);
    const errorKind = classifyFailure(reason);
    return { outcome: { kind: "error", errorKind, record: { cluster, status: "error", error_kind: errorKind, reason } } };
  }
}

type CheckOrOutcome =
  | { readonly passed: DraftCheckResult; readonly rule: Record<string, unknown> }
  | { readonly outcome: Outcome };

/**
 * The deterministic gate, in an order that keeps the run alive: the regex and
 * engine checks in a worker under a time budget, then scripts/gate-redos.py on
 * a passing fallback. Each can route this draft; none can stall the run, and a
 * draft that would fail check-rules-safety or the ReDoS gate is stopped here
 * rather than at the pre-push backstop, which would discard the whole run.
 */
async function gateDraft(c: ClusterCandidate, draft: SemanticDraft, ctx: AuthorContext): Promise<CheckOrOutcome> {
  const cluster = c.proposalRel;
  let result: DraftCheckResult;
  try {
    result = await runDraftCheckWithBudget({
      draft,
      candidate: c,
      allowlists: ctx.allowlists,
      benignSamples: ctx.benignSamples,
      foreign: ctx.foreign,
    });
  } catch (e) {
    return { outcome: gateDown(cluster, String(e)) };
  }
  if (!result.gate.ok || !result.rule) return { outcome: routed(cluster, result.gate.reason) };
  const redos = redosPrecheck((draft.fallback_regex ?? "").trim(), REPO_ROOT);
  if (redos.kind === "unavailable") return { outcome: gateDown(cluster, `ReDoS precheck could not run: ${redos.detail}`) };
  if (redos.kind === "backtracks") {
    return { outcome: routed(cluster, `fallback_regex backtracks catastrophically under scripts/gate-redos.py: ${redos.detail}`) };
  }
  return { passed: result, rule: result.rule };
}

/** Allocate the id only now, so a routed draft never burns one, and gate later drafts against this rule. */
function promote(
  c: ClusterCandidate,
  draft: SemanticDraft,
  gated: { readonly passed: DraftCheckResult; readonly rule: Record<string, unknown> },
  ctx: AuthorContext,
): Step {
  const id = ctx.idGen();
  const rule = { ...gated.rule, id };
  const newRule = writeRule(c, id, rule);
  const outcome: Outcome = {
    kind: "promoted",
    record: {
      cluster: c.proposalRel,
      status: DRY_RUN ? "would_promote" : "promoted",
      new_id: id,
      new_rule: newRule,
      fallback_regex: draft.fallback_regex,
      ...gated.passed.gate.metrics,
    },
  };
  return { outcome, ctx: { ...ctx, foreign: addPeer(ctx.foreign, rule) } };
}

async function authorOne(c: ClusterCandidate, ctx: AuthorContext): Promise<Step> {
  const requested = await draftFor(c, ctx);
  if ("outcome" in requested) return { outcome: requested.outcome, ctx };
  const gated = await gateDraft(c, requested.draft, ctx);
  if ("outcome" in gated) return { outcome: gated.outcome, ctx };
  return promote(c, requested.draft, gated, ctx);
}

/**
 * Load MEASUREMENT_CORPORA once for every draft. The 0-FP gate is only
 * meaningful with a real corpus: on a fresh checkout where
 * build-benign-corpus.ts never ran it could be empty, and every candidate would
 * pass vacuously. Abort loudly rather than author rules against that.
 */
function loadBenignCorpus(): readonly string[] {
  const samples = loadBenignSamples(REPO_ROOT);
  if (WRITE && samples.length < MIN_BENIGN_CORPUS) {
    console.error(
      `FATAL: benign corpus too small (${samples.length} < ${MIN_BENIGN_CORPUS}); ` +
        `the 0-FP gate cannot run safely. Run scripts/build-benign-corpus.ts first.`,
    );
    process.exit(1);
  }
  return samples;
}

/**
 * What check-rules-safety charges a new rule against besides MEASUREMENT_CORPORA:
 * research mentions (check 4) and every rule's true_negatives (check 5). Both
 * fail closed when writing: an empty mention corpus or an unreadable rule would
 * clear drafts of FPs nobody measured, and the backstop would then fail the run.
 */
function loadForeignRules(pending: PendingRules): ForeignRules {
  const mentions = loadCorpusTexts(join(REPO_ROOT, RESEARCH_MENTIONS_CORPUS));
  const tns = loadRuleTrueNegatives(RULES_BASE);
  const problems = [
    ...(mentions.length === 0 ? [`${RESEARCH_MENTIONS_CORPUS} is empty or missing`] : []),
    ...tns.errors,
  ];
  if (WRITE && problems.length > 0) {
    console.error(`FATAL: the cross-rule / research-mention gate cannot run safely: ${problems.slice(0, 3).join("; ")}`);
    process.exit(1);
  }
  return { mentions, ruleTrueNegatives: tns.samples, peers: pending.rules };
}

/**
 * The rules the PR already adds, or none without --base. Fails closed when
 * writing: a rule that cannot be read is a peer nobody gated against.
 */
function loadPendingOrExit(): PendingRules {
  if (!BASE_REF) return NO_PENDING;
  const pending = loadPendingRules(BASE_REF, REPO_ROOT);
  if (WRITE && pending.errors.length > 0) {
    console.error(`FATAL: cannot read the rules this PR already adds: ${pending.errors.slice(0, 3).join("; ")}`);
    process.exit(1);
  }
  return pending;
}

function perPrCapOrExit(): number {
  try {
    return parsePerPrCap(process.env.MAX_NEW_PER_PR);
  } catch (e) {
    console.error(`FATAL: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}

interface RunInputs {
  readonly corpusSize: number;
  readonly mentionsSize: number;
  readonly ruleTrueNegatives: number;
  readonly candidatesTotal: number;
  readonly skipped: readonly Skip[];
  readonly alreadyAuthored: number;
  readonly authoredBefore: number;
  readonly alreadyInPr: number;
  readonly budget: number;
}

function buildSummary(inputs: RunInputs, outcomes: readonly Outcome[]) {
  const count = (pred: (o: Outcome) => boolean) => outcomes.filter(pred).length;
  return {
    run_date: new Date().toISOString(),
    model: process.env.ATR_AUTHOR_MODEL || DEFAULT_MODEL,
    write: WRITE,
    benign_corpus_size: inputs.corpusSize,
    research_mentions_size: inputs.mentionsSize,
    rule_true_negatives: inputs.ruleTrueNegatives,
    candidates_total: inputs.candidatesTotal,
    candidates_attempted: outcomes.length,
    skipped_out_of_scope: inputs.skipped.length,
    skipped_quarantined: inputs.skipped.filter((s) => s.reason === QUARANTINE_REASON).length,
    skipped_already_authored: inputs.alreadyAuthored,
    skipped_authored_before: inputs.authoredBefore,
    rules_already_in_pr: inputs.alreadyInPr,
    promotion_budget: inputs.budget,
    promoted: count((o) => o.kind === "promoted"),
    routed_to_human: count((o) => o.kind === "routed"),
    errors: count((o) => o.kind === "error"),
    errors_infrastructure: count((o) => o.kind === "error" && o.errorKind === "infrastructure"),
    errors_content: count((o) => o.kind === "error" && o.errorKind === "content"),
    skipped: inputs.skipped.slice(0, 50),
    results: outcomes.map((o) => o.record),
  };
}

type Summary = ReturnType<typeof buildSummary>;

function reportSummary(summary: Summary): void {
  if (REPORT_PATH) {
    const abs = resolve(REPO_ROOT, REPORT_PATH);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, JSON.stringify(summary, null, 2), "utf-8");
  }
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::semantic-summary::${JSON.stringify({
      candidates: summary.candidates_total,
      attempted: summary.candidates_attempted,
      promoted: summary.promoted,
      routed_to_human: summary.routed_to_human,
      skipped_out_of_scope: summary.skipped_out_of_scope,
      skipped_already_authored: summary.skipped_already_authored,
      skipped_authored_before: summary.skipped_authored_before,
      errors: summary.errors,
      errors_infrastructure: summary.errors_infrastructure,
    })}`,
  );
}

/**
 * Fail loudly when the lane could not run at all. Exiting 0 here is what made
 * a dead lane look green: every attempted candidate died on an API error, no
 * rule was produced, and the workflow read "promoted 0" as "nothing to do".
 */
function exitOnLaneDown(summary: Summary): void {
  const attempted = summary.candidates_attempted;
  if (attempted > 0 && summary.promoted === 0 && summary.errors_infrastructure === attempted) {
    const firstReason = (summary.results.find((r) => r.status === "error")?.reason as string) ?? "unknown";
    console.error(
      `::error::semantic lane could not run: all ${attempted} attempted candidates failed with an infrastructure error. ` +
        `First failure: ${firstReason.slice(0, 300)}`,
    );
    process.exit(4);
  }
  if (summary.errors_infrastructure > 0) {
    console.error(
      `::warning::${summary.errors_infrastructure} of ${attempted} candidates failed with an infrastructure error; ` +
        `${summary.promoted} still promoted. Partial run, not a clean one.`,
    );
  }
}

/**
 * Author candidates in order. Each promotion returns the context the next
 * draft is gated against, so a later draft is also checked against the rules
 * this run already wrote (check-rules-safety's check 5 sees them as peers).
 */
export async function authorAll(candidates: readonly ClusterCandidate[], first: AuthorContext): Promise<Outcome[]> {
  const outcomes: Outcome[] = [];
  let ctx = first;
  for (const c of candidates) {
    const step = await authorOne(c, ctx);
    outcomes.push(step.outcome);
    ctx = step.ctx;
  }
  return outcomes;
}

async function main(): Promise<void> {
  if (!backendAvailable()) {
    emit({
      status: "no_backend",
      note:
        "No Claude backend. Set CLAUDE_CODE_OAUTH_TOKEN (preferred, subscription credit — run " +
        "`claude setup-token`) or ANTHROPIC_API_KEY (metered credit). Refusing to fabricate semantic rules.",
    });
    process.exit(2);
  }

  const { candidates: found, skipped } = findCandidates({
    repoRoot: REPO_ROOT,
    sourceFilter: SOURCE_FILTER,
    includeQuarantined: INCLUDE_QUARANTINED,
  });
  // Dedupe before capping. Slicing first would spend the whole --max budget
  // on clusters that already have a rule and author nothing new. A cluster
  // authored in an earlier rolling PR that was closed or had the rule removed
  // (--exclude-from, written by the workflow) is not authored again.
  const authoredEver = EXCLUDE_FROM ? readExcludeList(EXCLUDE_FROM) : new Set<string>();
  const { fresh: candidates, alreadyAuthored, authoredBefore } = selectCandidates(
    found,
    loadAuthoredClusters(),
    authoredEver,
  );
  if (!Number.isInteger(MAX_PROMOTE) || MAX_PROMOTE < 0) {
    console.error(`FATAL: --max must be a non-negative integer, got "${opt("--max")}"`);
    process.exit(1);
  }
  const pending = loadPendingOrExit();
  const perPrCap = perPrCapOrExit();
  const budget = promotionBudget(MAX_PROMOTE, pending.files.length, perPrCap);
  if (budget < MAX_PROMOTE) {
    console.log(
      `::notice::the PR already adds ${pending.files.length} rule(s) and check-rules-safety allows ${perPrCap} ` +
        `per PR, so this run takes on ${budget} candidate(s), not ${MAX_PROMOTE}`,
    );
  }
  const benignSamples = loadBenignCorpus();
  const foreign = loadForeignRules(pending);
  console.log(`[author-semantic] llm backend: ${describeBackend()}`);

  const ctx: AuthorContext = {
    requestDraft: callLlm,
    idGen: nextAtrId(openPrFilesOrExit()),
    benignSamples,
    allowlists: loadOwaspAllowlists(REPO_ROOT),
    foreign,
  };
  const outcomes = await authorAll(candidates.slice(0, budget), ctx);

  const summary = buildSummary(
    {
      corpusSize: benignSamples.length,
      mentionsSize: foreign.mentions.length,
      ruleTrueNegatives: foreign.ruleTrueNegatives.length,
      candidatesTotal: candidates.length,
      skipped,
      alreadyAuthored: alreadyAuthored.length,
      authoredBefore: authoredBefore.length,
      alreadyInPr: pending.files.length,
      budget,
    },
    outcomes,
  );
  reportSummary(summary);
  exitOnLaneDown(summary);
}

/**
 * Is this failure the lane being unable to run, rather than a candidate being
 * legitimately rejected?
 *
 * The distinction is load-bearing. `routed_to_human` means the gate looked at a
 * draft and said no — that is the lane working. An API error means no draft was
 * ever produced, and reporting that as "promoted 0" makes a dead lane
 * indistinguishable from a quiet one. On 2026-09-21 this workflow reported
 * success with promoted:0 / errors:8, where all eight were HTTP 400
 * "credit balance is too low". The run was green for days while the lane was dead.
 */
export function classifyFailure(reason: string): "infrastructure" | "content" {
  const r = reason.toLowerCase();
  const infra = [
    "credit balance", "insufficient_quota", "quota",
    "rate limit", "rate_limit", "429",
    "authentication", "invalid api key", "unauthorized", "401", "403",
    "overloaded", "529", "500", "502", "503", "504",
    "econnreset", "enotfound", "etimedout", "socket hang up", "fetch failed",
    // A timeout is the call never completing, not a draft being rejected. Missing
    // this is how a CLI timeout got filed as a content failure in testing.
    "timed out", "timeout", "aborted", "sigkill", "killed",
    // The CLI surfaces its own auth/quota problems in prose rather than status codes.
    "not logged in", "please run /login", "usage limit", "quota exceeded",
  ];
  return infra.some((needle) => r.includes(needle)) ? "infrastructure" : "content";
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
