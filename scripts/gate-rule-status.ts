/**
 * Rule status ratchet -- CI gate over the whole ATR rule corpus.
 *
 * WHAT IT PREVENTS
 *   `status: draft` means "this rule does not exist". src/engine.ts skips draft
 *   and deprecated rules in BOTH evaluation paths, before the lane gate and
 *   before any pattern is compiled:
 *
 *       if (rule.status === 'deprecated' || rule.status === 'draft') continue;
 *
 *   A draft rule therefore never fires -- not in hunt, not in alert, not in
 *   enforce, not in scanSkill. Nothing told the author that. The rule validates,
 *   its test_cases pass under the tooling that promotes drafts in-memory, the
 *   quality gate goes green, and it ships inert. One batch of 11 new rules was
 *   authored from an existing rule used as a template; 7 inherited
 *   `status: draft` from it and all 7 were dead on arrival.
 *
 *   This gate makes that state unreachable for new work: a rule may not carry
 *   `status: draft` unless it is a recorded, pre-existing exception.
 *
 * WHY A RATCHET INSTEAD OF A HARD GATE
 *   Same reasoning as maturity-fp-gate.yml and gate-re2-portability.ts: a large
 *   pre-existing backlog of draft rules exists, and reviving one is not a
 *   one-word edit -- an inert rule has never been measured against the benign
 *   corpus, so waking it up has to go through the FP gate first. Failing every
 *   PR until that backlog clears would stop all rule work. So this blocks NEW
 *   inert rules and lets the backlog drain on its own schedule, through
 *   data/rule-status-baseline.json.
 *
 * WHY FULL-SET AND NOT PR-DIFF SCOPED
 *   A diff-scoped gate is exactly what failed here. Rules reach this repo by
 *   doors that no `git diff base...HEAD` can see:
 *     - untracked files written to rules/ and gated before any commit
 *       (scripts/fn-mine-llm.ts does this),
 *     - the CVE collector and auto-crystallize, which commit straight to main.
 *   Comparing the whole working tree against a committed baseline sees every
 *   one of them, needs no git history, and works on a shallow checkout.
 *
 * WHAT FAILS THE BUILD
 *   - A rule carries `status: draft` and is not in the baseline. That covers a
 *     newly authored draft rule AND a previously live rule flipped to draft.
 *   - A rule file cannot be parsed, or carries no `status`. "Cannot determine
 *     the status" must never be reported as "not draft" -- that is the class of
 *     silent pass this gate exists to remove.
 *   - --strict-suspicious was requested and a baselined draft rule carries
 *     true_positives (see below).
 *
 * WHAT DOES NOT FAIL THE BUILD
 *   - A baselined draft rule that is still draft. That is the recorded backlog.
 *   - A baselined rule that left draft. Reported so the baseline can be
 *     tightened with --write-baseline, matching gate-re2-portability.ts.
 *
 * THE SUSPICIOUS-DRAFT WARNING
 *   A draft rule with a populated test_cases.true_positives block is a rule
 *   whose author believed it was working: they wrote the attack samples it is
 *   supposed to catch. Those are simultaneously the most misleading entries in
 *   the corpus and the best revival candidates, so they are always listed.
 *
 * KNOWN GAP (deliberate)
 *   Editing a baselined draft rule and leaving it draft stays green. Catching
 *   that needs either git (which reintroduces the blind spot above) or content
 *   hashes in the baseline (which churn on every cosmetic edit). The inflow
 *   this gate exists to stop is newly authored rules, and the not-in-baseline
 *   check covers those completely; the suspicious-draft list covers the rest by
 *   naming every inert rule that looks alive.
 *
 * USAGE
 *   npx tsx scripts/gate-rule-status.ts                    # gate
 *   npx tsx scripts/gate-rule-status.ts --json             # machine-readable
 *   npx tsx scripts/gate-rule-status.ts --strict-suspicious
 *   npx tsx scripts/gate-rule-status.ts --write-baseline   # tighten only
 */
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;

/** The status the engine drops silently. `deprecated` is dropped too, on purpose. */
export const GATED_STATUS = "draft";

export const BASELINE_NOTE =
  "Rules carrying `status: draft`, which src/engine.ts never evaluates in any lane. " +
  "Ratchet only -- entries may be removed as rules are revived, never added to " +
  "silence a new inert rule. See scripts/gate-rule-status.ts.";

/** Thrown when the given flags cannot produce a meaningful run. */
export class StatusGateUsageError extends Error {}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface StatusGateOptions {
  readonly writeBaseline: boolean;
  readonly strictSuspicious: boolean;
  readonly json: boolean;
}

export function parseCliOptions(argv: readonly string[]): StatusGateOptions {
  const known = new Set(["--write-baseline", "--strict-suspicious", "--json"]);
  const unknown = argv.filter((a) => a.startsWith("--") && !known.has(a));
  if (unknown.length > 0) {
    throw new StatusGateUsageError(`unknown flag(s): ${unknown.join(", ")}`);
  }
  return {
    writeBaseline: argv.includes("--write-baseline"),
    strictSuspicious: argv.includes("--strict-suspicious"),
    json: argv.includes("--json"),
  };
}

// ---------------------------------------------------------------------------
// Corpus scan
// ---------------------------------------------------------------------------

export interface RuleRecord {
  readonly id: string;
  /** Repo-relative path. */
  readonly file: string;
  readonly status: string;
  readonly maturity: string;
  readonly severity: string;
  readonly truePositives: number;
  readonly trueNegatives: number;
}

/** A file under rules/ whose status could not be established. Never a pass. */
export interface UnreadableRule {
  readonly file: string;
  readonly reason: string;
}

export interface CorpusScan {
  readonly rules: readonly RuleRecord[];
  readonly unreadable: readonly UnreadableRule[];
}

/** Every *.yaml under a directory tree, sorted for deterministic reports. */
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

function countCases(block: unknown, key: string): number {
  const cases = (block as Record<string, unknown> | undefined)?.[key];
  return Array.isArray(cases) ? cases.length : 0;
}

/**
 * Read one rule file. Returns either a record or the reason it could not be
 * read -- a parse failure is surfaced, never swallowed, because an unreadable
 * rule that silently drops out of the scan is indistinguishable from a clean one.
 */
export function readRule(absPath: string, repoRoot: string): RuleRecord | UnreadableRule {
  const file = relative(repoRoot, absPath);
  let doc: Record<string, unknown>;
  try {
    doc = yamlLoad(readFileSync(absPath, "utf-8")) as Record<string, unknown>;
  } catch (err) {
    return { file, reason: `YAML parse failed: ${(err as Error).message}` };
  }
  if (doc === null || typeof doc !== "object") return { file, reason: "not a YAML mapping" };
  const id = typeof doc.id === "string" ? doc.id : "";
  if (!id) return { file, reason: "no `id:` field" };
  const status = typeof doc.status === "string" ? doc.status : "";
  if (!status) return { file, reason: `no \`status:\` field (${id})` };
  return {
    id,
    file,
    status,
    maturity: typeof doc.maturity === "string" ? doc.maturity : "",
    severity: typeof doc.severity === "string" ? doc.severity : "",
    truePositives: countCases(doc.test_cases, "true_positives"),
    trueNegatives: countCases(doc.test_cases, "true_negatives"),
  };
}

export function scanCorpus(rulesDir: string, repoRoot: string): CorpusScan {
  const rules: RuleRecord[] = [];
  const unreadable: UnreadableRule[] = [];
  for (const abs of listRuleFiles(rulesDir)) {
    const r = readRule(abs, repoRoot);
    if ("id" in r) rules.push(r);
    else unreadable.push(r);
  }
  return { rules, unreadable };
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

export interface StatusBaseline {
  readonly generatedAt: string;
  readonly note: string;
  readonly corpus: { readonly rules: number; readonly draftRules: number };
  /** Rule ids allowed to remain `status: draft`. Sorted. */
  readonly knownDraft: readonly string[];
}

export const EMPTY_BASELINE: StatusBaseline = {
  generatedAt: "",
  note: BASELINE_NOTE,
  corpus: { rules: 0, draftRules: 0 },
  knownDraft: [],
};

/**
 * Parse and validate a baseline. Never trusts the shape on disk: a corrupt
 * file that read as an empty baseline would turn every backlog rule into a new
 * failure, and a corrupt file that read as "everything allowed" would turn the
 * gate into a no-op. Both are worse than refusing to run.
 */
export function parseBaseline(raw: string, source: string): StatusBaseline {
  let doc: Partial<StatusBaseline>;
  try {
    doc = JSON.parse(raw) as Partial<StatusBaseline>;
  } catch (err) {
    throw new StatusGateUsageError(`${source}: not valid JSON -- ${(err as Error).message}`);
  }
  const known = doc.knownDraft;
  if (!Array.isArray(known) || known.some((id) => typeof id !== "string")) {
    throw new StatusGateUsageError(`${source}: "knownDraft" must be an array of rule id strings`);
  }
  return { ...EMPTY_BASELINE, ...doc, knownDraft: [...known].sort() };
}

export function loadBaseline(path: string): StatusBaseline {
  if (!existsSync(path)) return EMPTY_BASELINE;
  return parseBaseline(readFileSync(path, "utf-8"), path);
}

/**
 * Tighten-only baseline update: entries whose rule left draft are dropped, and
 * nothing is ever added. Widening the baseline is the one move that would make
 * this gate lie, so it is not automatable -- a genuine new exception has to be
 * hand-written into the file, where CODEOWNERS review can see it.
 */
export function tightenBaseline(
  baseline: StatusBaseline,
  scan: CorpusScan,
  now: string,
): StatusBaseline {
  const drafts = draftIds(scan);
  const kept = baseline.knownDraft.filter((id) => drafts.has(id)).sort();
  return {
    generatedAt: now,
    note: BASELINE_NOTE,
    corpus: { rules: scan.rules.length, draftRules: drafts.size },
    knownDraft: kept,
  };
}

function draftIds(scan: CorpusScan): ReadonlySet<string> {
  return new Set(scan.rules.filter((r) => r.status === GATED_STATUS).map((r) => r.id));
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

export interface StatusComparison {
  /** Draft rules with no baseline entry. These fail the build. */
  readonly newDrafts: readonly RuleRecord[];
  /** Baselined draft rules still draft. Accepted backlog. */
  readonly grandfathered: readonly RuleRecord[];
  /** Grandfathered rules carrying true_positives -- inert but look alive. */
  readonly suspicious: readonly RuleRecord[];
  /** Baseline ids that are no longer draft (revived, or gone). Tighten these. */
  readonly resolved: readonly string[];
}

export function compareToBaseline(scan: CorpusScan, baseline: StatusBaseline): StatusComparison {
  const allowed = new Set(baseline.knownDraft);
  const drafts = scan.rules.filter((r) => r.status === GATED_STATUS);
  const grandfathered = drafts.filter((r) => allowed.has(r.id));
  const present = draftIds(scan);
  return {
    newDrafts: drafts.filter((r) => !allowed.has(r.id)),
    grandfathered,
    suspicious: grandfathered.filter((r) => r.truePositives > 0),
    resolved: baseline.knownDraft.filter((id) => !present.has(id)),
  };
}

// ---------------------------------------------------------------------------
// Engine self-check
// ---------------------------------------------------------------------------

export interface EngineSkip {
  /** 1-indexed lines of the `status === 'draft'` skip. Empty if it is gone. */
  readonly lines: readonly number[];
}

/**
 * Locate the skip this gate exists because of, and quote its real line numbers
 * rather than a number baked into an error string that rots on the next refactor.
 * An empty result is itself signal: if the engine stops dropping draft rules,
 * this gate has become obsolete and should be reconsidered, not left asserting
 * something that is no longer true.
 */
export function findEngineSkip(source: string): EngineSkip {
  const lines: number[] = [];
  source.split("\n").forEach((line, i) => {
    if (/rule\.status\s*===\s*['"]draft['"]/.test(line)) lines.push(i + 1);
  });
  return { lines };
}

function readEngineSkip(enginePath: string): EngineSkip {
  if (!existsSync(enginePath)) return { lines: [] };
  return findEngineSkip(readFileSync(enginePath, "utf-8"));
}

/** The sentence every failure has to carry: what draft means and what to do. */
export function draftExplanation(skip: EngineSkip): string {
  const where =
    skip.lines.length > 0
      ? `src/engine.ts:${skip.lines.join(" and :")}`
      : "src/engine.ts (the draft skip is GONE -- re-check whether this gate is still needed)";
  return (
    `draft rules are never evaluated by the engine (${where}); ` +
    `use status: experimental and control the lane via maturity ` +
    `(stable = enforce, test = alert, anything else = hunt only)`
  );
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/** Keep a CI log readable when the backlog is large. */
const MAX_LISTED = 20;

function renderList(records: readonly RuleRecord[]): string[] {
  const shown = records.slice(0, MAX_LISTED);
  const rest = records.length - shown.length;
  const lines = shown.map(
    (r) => `  - ${r.id}  [severity: ${r.severity || "?"}, maturity: ${r.maturity || "?"}]  ${r.file}`,
  );
  if (rest > 0) lines.push(`  ... and ${rest} more`);
  return lines;
}

export interface GateResult {
  readonly code: number;
  readonly lines: readonly string[];
  readonly comparison: StatusComparison;
}

function renderReport(
  scan: CorpusScan,
  comparison: StatusComparison,
  skip: EngineSkip,
  options: StatusGateOptions,
): readonly string[] {
  const { newDrafts, grandfathered, suspicious, resolved } = comparison;
  const out: string[] = [
    "",
    "=== ATR Rule Status GATE ===",
    `corpus: ${scan.rules.length} rules`,
    `inert (status: draft): ${grandfathered.length + newDrafts.length}` +
      ` (baseline allows ${grandfathered.length})`,
  ];

  if (scan.unreadable.length > 0) {
    out.push("", "GATE FAIL -- these files under rules/ have no determinable status:");
    out.push(...scan.unreadable.map((u) => `  - ${u.file}  ${u.reason}`));
    out.push("  A rule whose status cannot be read must not be assumed live.");
  }

  if (newDrafts.length > 0) {
    out.push("", `GATE FAIL -- ${newDrafts.length} rule(s) carry \`status: draft\` and are not baselined:`);
    out.push(...renderList(newDrafts));
    out.push("", `  ${draftExplanation(skip)}.`);
    out.push("  Fix the rule, not the baseline: change `status: draft` to `status: experimental`.");
    out.push("  Do NOT add these ids to data/rule-status-baseline.json -- that baseline is a");
    out.push("  record of pre-existing debt, and --write-baseline can only shrink it.");
  }

  if (suspicious.length > 0) {
    const verdict = options.strictSuspicious ? "GATE FAIL" : "WARN";
    out.push("", `${verdict} -- ${suspicious.length} baselined draft rule(s) carry true_positives:`);
    out.push(...renderList(suspicious));
    out.push("  Their author wrote the attack samples these are meant to catch, so they read");
    out.push("  as working rules. They fire on nothing. Best revival candidates: run them");
    out.push("  through scripts/gate-promotion-fp.ts --ids, then flip status to experimental.");
  }

  if (resolved.length > 0) {
    out.push("", `RATCHET -- ${resolved.length} baselined rule(s) left draft; tighten the baseline:`);
    out.push(...resolved.slice(0, MAX_LISTED).map((id) => `  + ${id}`));
    if (resolved.length > MAX_LISTED) out.push(`  ... and ${resolved.length - MAX_LISTED} more`);
    out.push("  (run: npx tsx scripts/gate-rule-status.ts --write-baseline)");
  }
  return out;
}

export function resolveExitCode(
  scan: CorpusScan,
  comparison: StatusComparison,
  strictSuspicious: boolean,
): number {
  if (scan.unreadable.length > 0) return EXIT_FAIL;
  if (comparison.newDrafts.length > 0) return EXIT_FAIL;
  if (strictSuspicious && comparison.suspicious.length > 0) return EXIT_FAIL;
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

export interface StatusGateDeps {
  readonly repoRoot: string;
  readonly rulesDir: string;
  readonly baselinePath: string;
  readonly enginePath: string;
  readonly now: () => string;
}

export function defaultDeps(): StatusGateDeps {
  return {
    repoRoot: REPO_ROOT,
    rulesDir: join(REPO_ROOT, "rules"),
    baselinePath: join(REPO_ROOT, "data/rule-status-baseline.json"),
    enginePath: join(REPO_ROOT, "src/engine.ts"),
    now: () => new Date().toISOString(),
  };
}

/** Write the tightened baseline and say plainly what was refused. */
function writeTightenedBaseline(
  baseline: StatusBaseline,
  scan: CorpusScan,
  comparison: StatusComparison,
  deps: StatusGateDeps,
): GateResult {
  const next = tightenBaseline(baseline, scan, deps.now());
  writeFileSync(deps.baselinePath, `${JSON.stringify(next, null, 2)}\n`, "utf-8");
  const dropped = baseline.knownDraft.length - next.knownDraft.length;
  const lines = [
    `[status-gate] baseline tightened: ${baseline.knownDraft.length} -> ${next.knownDraft.length} entr(ies) (-${dropped})`,
  ];
  if (comparison.newDrafts.length > 0) {
    lines.push(
      `[status-gate] ${comparison.newDrafts.length} un-baselined draft rule(s) were NOT added --`,
      "             --write-baseline only shrinks. Fix those rules instead:",
      ...renderList(comparison.newDrafts),
    );
  }
  return { code: EXIT_OK, lines, comparison };
}

function renderJson(scan: CorpusScan, comparison: StatusComparison): string {
  return JSON.stringify(
    {
      rules: scan.rules.length,
      unreadable: scan.unreadable,
      newDrafts: comparison.newDrafts,
      grandfathered: comparison.grandfathered.length,
      suspicious: comparison.suspicious.map((r) => r.id),
      resolved: comparison.resolved,
    },
    null,
    2,
  );
}

export function runGate(
  options: StatusGateOptions,
  deps: StatusGateDeps = defaultDeps(),
): GateResult {
  const scan = scanCorpus(deps.rulesDir, deps.repoRoot);
  const baseline = loadBaseline(deps.baselinePath);
  const comparison = compareToBaseline(scan, baseline);

  if (options.writeBaseline) {
    return writeTightenedBaseline(baseline, scan, comparison, deps);
  }

  const code = resolveExitCode(scan, comparison, options.strictSuspicious);
  if (options.json) return { code, lines: [renderJson(scan, comparison)], comparison };

  const skip = readEngineSkip(deps.enginePath);
  const lines = [
    ...renderReport(scan, comparison, skip, options),
    "",
    code === EXIT_OK ? "GATE PASS -- no new inert rule." : "",
    "",
  ];
  return { code, lines, comparison };
}

export function main(argv: readonly string[], deps: StatusGateDeps = defaultDeps()): number {
  let options: StatusGateOptions;
  try {
    options = parseCliOptions(argv);
  } catch (e: unknown) {
    if (e instanceof StatusGateUsageError) {
      console.error(`[status-gate] usage error: ${e.message}`);
      return EXIT_USAGE;
    }
    throw e;
  }
  try {
    const { code, lines } = runGate(options, deps);
    console.log(lines.join("\n"));
    return code;
  } catch (e: unknown) {
    if (e instanceof StatusGateUsageError) {
      console.error(`[status-gate] cannot run: ${e.message}`);
      return EXIT_USAGE;
    }
    throw e;
  }
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
