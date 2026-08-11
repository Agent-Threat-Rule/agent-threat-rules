/**
 * Corpus visibility ratchet -- CI gate over the whole ATR rule corpus.
 *
 * WHAT IT MEASURES
 *   For every rule: how many of the benign samples in MEASUREMENT_CORPORA could
 *   POSSIBLY have matched it. Not how many did -- how many could. It extracts
 *   the literal strings a match requires (scripts/lib/regex-literals.ts) and
 *   counts the benign samples that contain them (scripts/lib/literal-index.ts).
 *   That count is the rule's VISIBILITY.
 *
 * WHY IT EXISTS
 *   scripts/gate-promotion-fp.ts scores a rule against 5,352 benign samples and
 *   passes it at 0 false positives. Five rules cleared that gate with a clean 0
 *   and were then overturned by a reviewer who wrote his own benign samples by
 *   hand: they fired on 20%, 42%, 47%, 50% and 57% of them. Nothing had gone
 *   wrong with the FP gate. The corpus simply did not contain the shapes:
 *
 *       torsocks  0 occurrences   .onion  0   "run each one"  0   "scp "  2
 *
 *   A Tor rule scoring 0 FP on a corpus with no Tor in it is not a clean rule.
 *   It is an unasked question reported as an answer. This gate names that state
 *   so it stops being indistinguishable from precision.
 *
 * THE THREE TIERS
 *   blind     visibility 0 -- no benign sample can match this rule. Its 0 FP
 *             carries exactly zero bits of information.
 *   thin      0 < visibility < VISIBILITY_FLOOR. Rule of three: observing 0 FP
 *             over V candidate samples bounds the FP rate among matchable
 *             inputs at roughly 3/V with 95% confidence. At V=2 that bound is
 *             150% -- i.e. no bound at all. The five overturned rules sat here
 *             or below.
 *   measured  visibility >= VISIBILITY_FLOOR. A 0 here is evidence.
 *
 * WHY "BLIND" IS NOT AUTOMATICALLY A BAD RULE
 *   Plenty of good rules are blind on purpose. A rule keying on rot13-piped-to-
 *   shell, or on stripping C2PA provenance metadata, describes a string nobody
 *   writes by accident, so of course a benign corpus contains none. The defect
 *   is never "your rule is narrow". The defect is CLAIMING MEASURED PRECISION
 *   FROM A CORPUS THAT COULD NOT HAVE PRODUCED A FALSE POSITIVE. So the gate
 *   does not ask authors to widen rules. It asks for the missing half of the
 *   experiment: benign samples that DO contain the rule's literals, written as
 *   the most plausible legitimate use the author can think of. Add them to
 *   data/benign-corpus-extended/ and re-run the FP gate. If the rule stays
 *   silent, the 0 is now real. If it fires, the rule was judgment-shaped all
 *   along and must not enter the enforce lane -- which is the finding, arriving
 *   before shipping instead of after.
 *
 * WHY A RATCHET INSTEAD OF A HARD GATE
 *   Same shape as gate-rule-status.ts and gate-re2-portability.ts, for the same
 *   reason: a large pre-existing population is below the floor, and clearing it
 *   means authoring benign corpus samples, not editing YAML. Failing every PR
 *   until that is done would stop all rule work. So this freezes the current
 *   state in data/corpus-visibility-baseline.json and blocks only growth and
 *   regression.
 *
 * WHY FULL-SET AND NOT PR-DIFF SCOPED
 *   Rules reach this repo through doors no `git diff base...HEAD` can see:
 *   untracked files written straight into rules/ and gated before any commit
 *   (scripts/fn-mine-llm.ts), plus the CVE collector and auto-crystallize,
 *   which commit to main. Comparing the whole tree to a committed baseline sees
 *   all of them and needs no git history.
 *
 * WHAT FAILS THE BUILD
 *   - A blind or thin rule with no baseline entry. New rule, or a rule whose
 *     pattern was narrowed until the corpus stopped being able to see it.
 *   - A baselined rule that got worse (thin -> blind).
 *   - A file under rules/ whose detection cannot be read. "Could not determine
 *     visibility" must never be reported as visible; that is the exact class of
 *     silent pass this gate exists to remove.
 *   - --strict-claims and a baselined blind/thin rule sits in the enforce lane.
 *
 * WHAT DOES NOT FAIL THE BUILD
 *   - A baselined rule still at its recorded tier. That is the frozen debt.
 *   - A baselined rule that improved. Reported so --write-baseline can tighten.
 *   - Enforce-lane rules below the floor, by default. They are listed loudly
 *     because a maturity:stable rule whose FP evidence is vacuous is the worst
 *     case this gate knows how to find, but failing on the existing set would
 *     make the gate unlandable. --strict-claims turns it into a failure.
 *
 * SOUNDNESS
 *   The literal extractor only ever UNDER-claims what a pattern requires (see
 *   its header). So this gate can miss a blind rule; it cannot invent one. A
 *   pattern it cannot analyse is reported as visible, never as blind.
 *
 * THE GUARANTEE IS ONE-SIDED. READ THIS BEFORE QUOTING A PASS.
 *   "blind" is a proof: no benign sample can match, so the 0 FP is vacuous.
 *   "measured" is NOT a proof. Visibility counts samples containing the
 *   required LITERALS and ignores the proximity and ordering the regex also
 *   demands, so it is an upper bound and can be very loose. A rule built from
 *   common words plus tight `[^\n]{0,40}` gaps scores high here while the
 *   corpus never actually exercised it.
 *
 *   Measured, not hypothetical: of the five rules that provoked this gate, it
 *   catches the Tor rule (visibility 0, `torsocks`/`.onion` absent) and the scp
 *   rule (visibility 3). It does NOT catch the remote-instruction-channel rule,
 *   which scores 1585 because its vocabulary is fetch/run/command/every -- all
 *   common -- and its selectivity is entirely structural. A reviewer's
 *   hand-written benign samples fired it anyway. Structural selectivity is
 *   outside what a literal-frequency gate can see, and no threshold change
 *   would fix that. This gate raises the floor; it does not replace reading the
 *   rule.
 *
 * KNOWN GAPS (deliberate)
 *   - Visibility counts samples containing the required literals, ignoring the
 *     distance and ordering constraints between them. It is an upper bound on
 *     what could match, which is the safe direction: it never understates.
 *   - A baselined rule edited while staying at the same tier stays green, same
 *     trade-off gate-rule-status.ts documents.
 *   - Conditions on fields a text corpus cannot fill (tool_name, trace.*,
 *     behavioral.*) count as zero visibility, matching the NOT MEASURED report
 *     that gate-promotion-fp.ts already prints for them.
 *
 * USAGE
 *   npx tsx scripts/gate-corpus-visibility.ts                  # gate
 *   npx tsx scripts/gate-corpus-visibility.ts --json           # machine-readable
 *   npx tsx scripts/gate-corpus-visibility.ts --explain ATR-2026-00075
 *   npx tsx scripts/gate-corpus-visibility.ts --verify-blind   # audit the gate itself
 *   npx tsx scripts/gate-corpus-visibility.ts --strict-claims
 *   npx tsx scripts/gate-corpus-visibility.ts --write-baseline # tighten only
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MEASUREMENT_CORPORA,
  loadBenignSamples,
} from "./lib/benign-corpus.js";
import {
  buildLiteralIndex,
  documentFrequencies,
  frequencyMap,
} from "./lib/literal-index.js";
import { literalsOf } from "./lib/regex-literals.js";
import { ENFORCE_LANE_MATURITIES, isInertStatus } from "./lib/corpus-event.js";
import {
  BASELINE_PATH,
  BASELINE_NOTE,
  EMPTY_BASELINE,
  compareToBaseline,
  loadBaseline,
  tightenBaseline,
  type VisibilityBaseline,
  type VisibilityComparison,
} from "./lib/visibility-baseline.js";
import {
  VISIBILITY_FLOOR,
  scanRuleCorpus,
  measureVisibility,
  type RuleVisibility,
  type RuleCorpusScan,
} from "./lib/visibility-scan.js";
import { verifyBlindConditions, type VerifyResult } from "./lib/visibility-verify.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;

export class VisibilityGateUsageError extends Error {}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface VisibilityGateOptions {
  readonly writeBaseline: boolean;
  /** One-shot: create the baseline that freezes the pre-existing debt. */
  readonly bootstrapBaseline: boolean;
  readonly strictClaims: boolean;
  /** Execute every blind condition for real and fail if any of them matches. */
  readonly verifyBlind: boolean;
  readonly json: boolean;
  readonly explain: string | null;
}

const KNOWN_FLAGS = new Set([
  "--write-baseline",
  "--bootstrap-baseline",
  "--strict-claims",
  "--verify-blind",
  "--json",
  "--explain",
]);

export function parseCliOptions(argv: readonly string[]): VisibilityGateOptions {
  const unknown = argv.filter((a) => a.startsWith("--") && !KNOWN_FLAGS.has(a));
  if (unknown.length > 0) {
    throw new VisibilityGateUsageError(`unknown flag(s): ${unknown.join(", ")}`);
  }
  const at = argv.indexOf("--explain");
  const explain = at < 0 ? null : (argv[at + 1] ?? "");
  if (explain !== null && (explain === "" || explain.startsWith("--"))) {
    throw new VisibilityGateUsageError("--explain requires a rule id");
  }
  const writeBaseline = argv.includes("--write-baseline");
  const bootstrapBaseline = argv.includes("--bootstrap-baseline");
  if (writeBaseline && bootstrapBaseline) {
    throw new VisibilityGateUsageError(
      "--write-baseline and --bootstrap-baseline are mutually exclusive: one only " +
        "shrinks an existing record, the other creates the initial one.",
    );
  }
  return {
    writeBaseline,
    bootstrapBaseline,
    strictClaims: argv.includes("--strict-claims"),
    verifyBlind: argv.includes("--verify-blind"),
    json: argv.includes("--json"),
    explain,
  };
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

export interface VisibilityRun {
  readonly scan: RuleCorpusScan;
  readonly results: readonly RuleVisibility[];
  /** Lowercased benign samples, retained so --verify-blind can re-run them. */
  readonly samples: readonly string[];
  readonly sampleCount: number;
  readonly literalCount: number;
  readonly frequencies: ReadonlyMap<string, number>;
}

/**
 * One pass over the corpus for every literal every rule requires.
 *
 * The literals are pooled across all 783 rules before the corpus is touched:
 * per-rule scanning would re-read 32M characters 783 times, and a gate nobody
 * is willing to wait for is a gate that gets deleted.
 */
export function runMeasurement(repoRoot: string): VisibilityRun {
  const scan = scanRuleCorpus(join(repoRoot, "rules"), repoRoot);
  const pool = new Set<string>();
  for (const rule of scan.rules) {
    for (const cond of rule.conditions) {
      for (const lit of literalsOf(cond.requirement)) pool.add(lit);
    }
  }
  const literals = [...pool].sort();
  // Lowercased once, up front: the literal index, --verify-blind and the engine
  // must all see the same text, and every ATR condition compiles case-insensitive.
  const samples = loadBenignSamples(repoRoot).map((s) => s.toLowerCase());
  const index = buildLiteralIndex(literals);
  const frequencies = frequencyMap(index, documentFrequencies(index, samples));
  const results = scan.rules.map((rule) =>
    measureVisibility(rule, frequencies, samples.length),
  );
  return {
    scan,
    results,
    samples,
    sampleCount: samples.length,
    literalCount: literals.length,
    frequencies,
  };
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const MAX_LISTED = 25;

function describe(r: RuleVisibility): string {
  const lane = ENFORCE_LANE_MATURITIES.has(r.maturity) ? " ENFORCE-LANE" : "";
  const inert = isInertStatus(r.status) ? ` status:${r.status}` : "";
  const paths = `${r.blindConditions}/${r.conditions.length} unreachable condition(s)`;
  return (
    `  - ${r.id}  visibility=${r.visibility} (widest ${r.widest}) tier=${r.tier}` +
    `${lane}${inert}  ${paths}  ${r.file}`
  );
}

function renderList(rules: readonly RuleVisibility[]): string[] {
  const shown = rules.slice(0, MAX_LISTED).map(describe);
  const rest = rules.length - Math.min(rules.length, MAX_LISTED);
  if (rest > 0) shown.push(`  ... and ${rest} more (use --json for the full list)`);
  return shown;
}

const REMEDY = [
  "  A rule the benign corpus cannot match has NOT been measured by",
  "  scripts/gate-promotion-fp.ts, whatever number it printed. The remedy is not",
  "  to widen the rule -- it is to supply the missing half of the experiment:",
  "",
  "    1. Write benign samples that DO contain this rule's literals, as the most",
  "       plausible LEGITIMATE use you can construct (docs, tutorials, admin",
  "       runbooks, test fixtures). Add them to data/benign-corpus-extended/.",
  "    2. Re-run: npx tsx scripts/gate-promotion-fp.ts --ids <ids-file>",
  "    3. Silent on those samples -> the 0 FP is now real evidence.",
  "       Fires on them -> the rule is judgment-shaped (a neutral action plus an",
  "       intent call). Those cannot be made safe by tightening the regex and",
  "       must not enter the enforce lane.",
  "",
  "  Do NOT add ids to data/corpus-visibility-baseline.json. That file records",
  "  pre-existing debt and --write-baseline can only shrink it.",
];

function renderReport(
  run: VisibilityRun,
  comparison: VisibilityComparison,
  options: VisibilityGateOptions,
): readonly string[] {
  const tiers = { blind: 0, thin: 0, measured: 0 };
  for (const r of run.results) tiers[r.tier] += 1;
  const out: string[] = [
    "",
    "=== ATR Corpus Visibility GATE ===",
    `corpus:   ${run.sampleCount} benign samples from ${MEASUREMENT_CORPORA.join(", ")}`,
    `rules:    ${run.scan.rules.length} scanned, ${run.literalCount} distinct required literals`,
    `tiers:    blind ${tiers.blind} · thin ${tiers.thin} (< ${VISIBILITY_FLOOR}) · measured ${tiers.measured}`,
    `baseline: ${comparison.baselineSize} rule(s) recorded below the floor`,
  ];

  if (run.scan.unreadable.length > 0) {
    out.push("", "GATE FAIL -- these files under rules/ have no readable detection:");
    out.push(...run.scan.unreadable.map((u) => `  - ${u.file}  ${u.reason}`));
    out.push("  A rule whose visibility cannot be computed must not be assumed visible.");
  }

  if (comparison.newlyUnmeasured.length > 0) {
    out.push(
      "",
      `GATE FAIL -- ${comparison.newlyUnmeasured.length} rule(s) the benign corpus cannot meaningfully test,` +
        " and which are not baselined:",
    );
    out.push(...renderList(comparison.newlyUnmeasured));
    out.push("", ...REMEDY);
  }

  if (comparison.regressed.length > 0) {
    out.push(
      "",
      `GATE FAIL -- ${comparison.regressed.length} baselined rule(s) got LESS visible than recorded:`,
    );
    out.push(...renderList(comparison.regressed));
    out.push("  Either the rule was narrowed or the corpus lost the samples that saw it.");
  }

  if (comparison.enforceLaneDebt.length > 0) {
    const verdict = options.strictClaims ? "GATE FAIL" : "WARN";
    out.push(
      "",
      `${verdict} -- ${comparison.enforceLaneDebt.length} rule(s) below the visibility floor are in the` +
        " ENFORCE lane (maturity stable/production = auto-block):",
    );
    out.push(...renderList(comparison.enforceLaneDebt));
    out.push("  These auto-block on evidence the benign corpus could not have produced.");
    out.push("  Highest-value work in this repo: give each one benign counter-samples,");
    out.push("  then re-run gate-promotion-fp.ts and believe whatever it says next.");
  }

  if (comparison.resolved.length > 0) {
    out.push(
      "",
      `RATCHET -- ${comparison.resolved.length} baselined rule(s) improved; tighten the baseline:`,
    );
    out.push(...comparison.resolved.slice(0, MAX_LISTED).map((id) => `  + ${id}`));
    if (comparison.resolved.length > MAX_LISTED) {
      out.push(`  ... and ${comparison.resolved.length - MAX_LISTED} more`);
    }
    out.push("  (run: npx tsx scripts/gate-corpus-visibility.ts --write-baseline)");
  }
  return out;
}

/** Author-facing view of one rule: which literal is starving it. */
function renderExplain(run: VisibilityRun, id: string): readonly string[] {
  const rule = run.results.find((r) => r.id === id);
  if (rule === undefined) return [`[visibility] no rule with id ${id} under rules/`];
  const out = [
    "",
    `=== ${rule.id} — ${rule.file}`,
    `visibility ${rule.visibility} / ${run.sampleCount} benign samples · tier ${rule.tier}` +
      ` · detection.condition: ${rule.combinator}`,
    "",
  ];
  rule.conditions.forEach((cond, i) => {
    out.push(`condition ${i + 1}  field=${cond.field}  visibility=${cond.visibility}`);
    if (cond.note !== null) out.push(`  ${cond.note}`);
    for (const term of cond.requirement.alternatives) {
      const parts = term.map(
        (lit) => `${JSON.stringify(lit)}=${run.frequencies.get(lit) ?? 0}`,
      );
      out.push(`  requires all of: ${parts.join(" AND ") || "(nothing)"}`);
    }
    out.push("");
  });
  out.push(
    "A literal at 0 is a shape this corpus has never seen. Every alternative",
    "containing one is unreachable, and the rule's 0 FP says nothing about it.",
    "",
  );
  return out;
}

function renderJson(
  run: VisibilityRun,
  comparison: VisibilityComparison,
  verification: VerifyResult | null,
): string {
  return JSON.stringify(
    {
      corpora: MEASUREMENT_CORPORA,
      selfCheck: verification,
      samples: run.sampleCount,
      distinctLiterals: run.literalCount,
      visibilityFloor: VISIBILITY_FLOOR,
      unreadable: run.scan.unreadable,
      rules: run.results.map((r) => ({
        id: r.id,
        file: r.file,
        status: r.status,
        maturity: r.maturity,
        visibility: r.visibility,
        widest: r.widest,
        blindConditions: r.blindConditions,
        tier: r.tier,
        conditions: r.conditions.map((c, i) => ({
          index: i,
          field: c.field,
          visibility: c.visibility,
          unmeasurable: c.note,
        })),
      })),
      newlyUnmeasured: comparison.newlyUnmeasured.map((r) => r.id),
      regressed: comparison.regressed.map((r) => r.id),
      enforceLaneDebt: comparison.enforceLaneDebt.map((r) => r.id),
      resolved: comparison.resolved,
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

export function resolveExitCode(
  run: VisibilityRun,
  comparison: VisibilityComparison,
  strictClaims: boolean,
  verification: VerifyResult | null = null,
): number {
  if (run.scan.unreadable.length > 0) return EXIT_FAIL;
  if (verification !== null && verification.violations.length > 0) return EXIT_FAIL;
  if (comparison.newlyUnmeasured.length > 0) return EXIT_FAIL;
  if (comparison.regressed.length > 0) return EXIT_FAIL;
  if (strictClaims && comparison.enforceLaneDebt.length > 0) return EXIT_FAIL;
  return EXIT_OK;
}

/** The gate auditing itself: report what the differential run found. */
function renderVerification(v: VerifyResult): readonly string[] {
  if (v.violations.length === 0) {
    return [
      "",
      `SELF-CHECK -- executed ${v.executed} blind condition(s) against the corpus for real;` +
        ` none matched${v.uncompilable > 0 ? ` (${v.uncompilable} would not compile)` : ""}.`,
    ];
  }
  return [
    "",
    `GATE FAIL (self-check) -- ${v.violations.length} condition(s) reported blind actually MATCH a benign sample.`,
    "  The literal extractor over-claimed what these patterns require, so this run's",
    "  blind/thin verdicts cannot be trusted. Fix scripts/lib/regex-literals.ts.",
    ...v.violations
      .slice(0, MAX_LISTED)
      .map(
        (x) =>
          `  - ${x.ruleId} cond#${x.conditionIndex} @ sample ${x.sampleIndex}: ${x.pattern.slice(0, 100)}`,
      ),
  ];
}

export interface GateResult {
  readonly code: number;
  readonly lines: readonly string[];
}

export interface VisibilityGateDeps {
  readonly repoRoot: string;
  readonly baselinePath: string;
  readonly now: () => string;
}

export function defaultDeps(): VisibilityGateDeps {
  return {
    repoRoot: REPO_ROOT,
    baselinePath: join(REPO_ROOT, BASELINE_PATH),
    now: () => new Date().toISOString(),
  };
}

function writeBaselineFile(path: string, baseline: VisibilityBaseline): void {
  writeFileSync(path, `${JSON.stringify(baseline, null, 2)}\n`, "utf-8");
}

function writeTightened(
  baseline: VisibilityBaseline,
  run: VisibilityRun,
  comparison: VisibilityComparison,
  deps: VisibilityGateDeps,
): GateResult {
  const next = tightenBaseline(
    baseline,
    run.results,
    deps.now(),
    run.sampleCount,
    VISIBILITY_FLOOR,
  );
  writeBaselineFile(deps.baselinePath, next);
  const before = Object.keys(baseline.knownUnmeasured).length;
  const after = Object.keys(next.knownUnmeasured).length;
  const lines = [`[visibility-gate] baseline: ${before} -> ${after} entr(ies)`];
  if (comparison.newlyUnmeasured.length > 0) {
    lines.push(
      `[visibility-gate] ${comparison.newlyUnmeasured.length} un-baselined rule(s) below the floor were NOT`,
      "                  added -- --write-baseline only shrinks. Fix those instead:",
      ...renderList(comparison.newlyUnmeasured),
    );
  }
  return { code: EXIT_OK, lines };
}

/**
 * Create the initial record of pre-existing debt.
 *
 * This is the only path that may ADD entries, so it refuses to run when the
 * baseline already exists. Without that refusal it would be a one-flag reset
 * button for the whole gate -- run it after adding a blind rule and the failure
 * becomes recorded debt, which is precisely the laundering the ratchet forbids.
 */
function bootstrapBaseline(
  run: VisibilityRun,
  deps: VisibilityGateDeps,
): GateResult {
  if (existsSync(deps.baselinePath)) {
    throw new VisibilityGateUsageError(
      `${deps.baselinePath} already exists. --bootstrap-baseline may only create the ` +
        "initial record; use --write-baseline, which can only shrink it.",
    );
  }
  const below = run.results.filter((r) => r.tier !== "measured");
  const baseline: VisibilityBaseline = {
    generatedAt: deps.now(),
    note: BASELINE_NOTE,
    visibilityFloor: VISIBILITY_FLOOR,
    corpus: { samples: run.sampleCount, rules: run.results.length },
    knownUnmeasured: Object.fromEntries(
      below
        .map((r) => [r.id, r.tier] as const)
        .sort(([a], [b]) => a.localeCompare(b)),
    ),
  };
  writeBaselineFile(deps.baselinePath, baseline);
  return {
    code: EXIT_OK,
    lines: [
      `[visibility-gate] wrote ${below.length} pre-existing entr(ies) -> ${deps.baselinePath}`,
      "[visibility-gate] this is frozen debt, not a clean bill of health.",
    ],
  };
}

export function runGate(
  options: VisibilityGateOptions,
  deps: VisibilityGateDeps = defaultDeps(),
): GateResult {
  const run = runMeasurement(deps.repoRoot);
  const baseline = existsSync(deps.baselinePath)
    ? loadBaseline(deps.baselinePath)
    : EMPTY_BASELINE;
  const comparison = compareToBaseline(run.results, baseline);

  if (options.explain !== null) {
    return { code: EXIT_OK, lines: renderExplain(run, options.explain) };
  }
  if (options.bootstrapBaseline) {
    return bootstrapBaseline(run, deps);
  }
  if (options.writeBaseline) {
    return writeTightened(baseline, run, comparison, deps);
  }

  const verification = options.verifyBlind
    ? verifyBlindConditions(run.results, run.samples)
    : null;
  const code = resolveExitCode(run, comparison, options.strictClaims, verification);
  if (options.json) return { code, lines: [renderJson(run, comparison, verification)] };
  return {
    code,
    lines: [
      ...renderReport(run, comparison, options),
      ...(verification === null ? [] : renderVerification(verification)),
      "",
      code === EXIT_OK
        ? "GATE PASS -- no rule newly claims precision the corpus PROVABLY could not have\n" +
          "tested. Visibility is an upper bound: a high number is not a certificate that\n" +
          "the corpus exercised the rule, only that this gate cannot prove it did not."
        : "",
      "",
    ],
  };
}

export function main(
  argv: readonly string[],
  deps: VisibilityGateDeps = defaultDeps(),
): number {
  let options: VisibilityGateOptions;
  try {
    options = parseCliOptions(argv);
  } catch (e: unknown) {
    if (e instanceof VisibilityGateUsageError) {
      console.error(`[visibility-gate] usage error: ${e.message}`);
      return EXIT_USAGE;
    }
    throw e;
  }
  try {
    const { code, lines } = runGate(options, deps);
    console.log(lines.join("\n"));
    return code;
  } catch (e: unknown) {
    if (e instanceof VisibilityGateUsageError) {
      console.error(`[visibility-gate] cannot run: ${e.message}`);
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
