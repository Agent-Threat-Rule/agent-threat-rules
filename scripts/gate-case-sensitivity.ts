#!/usr/bin/env npx tsx
/**
 * Case-sensitivity ratchet -- CI gate over the whole ATR rule corpus.
 *
 * WHY THIS EXISTS
 *   The engine compiles every array-format `operator: regex` condition
 *   case-insensitively. regexConditionSpec() in src/engine.ts strips a leading
 *   inline flag group and returns the flags `i` (or `iu`) whether or not the
 *   author wrote (?i), and both of the engine's compile sites use it. Letter case
 *   therefore distinguishes nothing at runtime: [A-OQ-Za-z_] does not exclude a
 *   capital P, and AKIA[0-9A-Z]{16} also matches "akia..." in lowercase. A
 *   condition whose author leaned on letter case to keep a benign input out lets
 *   it in, and nothing else says so -- validate-rules.ts checks structure and the
 *   benign gate checks a fixed corpus.
 *
 * WHAT IT CHECKS
 *   Every regex condition whose leading inline flag group does not include `i` is
 *   compiled twice from the engine's own regexConditionSpec(): with the engine's
 *   flags, and with the same flags minus `i` -- the pattern as written. A FINDING
 *   is one of the rule's own true_negatives that the condition matches under the
 *   engine's flags and does not match as written. The samples are the texts
 *   src/testcase-event.ts builds for each test case, the same builder the rule's
 *   own test run uses, so object-shaped inputs and tool_response / tool_args /
 *   user_input cases are read rather than skipped.
 *
 * WHY THE FLAGS ARE IMPORTED, NOT RE-DERIVED
 *   The first version of this gate kept its own copy of the engine's flag
 *   selection. The engine then started setting `u` for literal astral characters
 *   as well as for \u{...} and \p{...}; the copy did not follow, and without `u` a
 *   class range written with astral literals is a SyntaxError, so the gate skipped
 *   every such condition without saying so. tests/gate-case-sensitivity.test.ts
 *   fails if the gate and the engine ever compile a condition differently.
 *
 * WHY ONLY THE RULE'S BENIGN SAMPLES, AS WRITTEN
 *   - Not the true positives. The forced `i` also lets a rule catch the uppercase
 *     spelling of its own attack; that is the flag helping, not a defect.
 *   - Not case-permuted copies of the samples. The first version also probed each
 *     sample lower-, upper- and title-cased. Under the engine's flags a case
 *     variant matches exactly when the original does, so a variant can only add a
 *     finding where the pattern as written already matches the original -- where
 *     nothing is being kept out at all. On 2026-10-16 that was 11 of 13 findings,
 *     and none of the 13 was a defect.
 *
 * WHAT A FINDING MEANS
 *   The condition, read literally, keeps one of its own benign samples out by
 *   letter case, and the engine lets it in. The rule may still stay silent on the
 *   sample -- another condition can reject it, and the rule's own test run checks
 *   that -- so a finding is a condition that misdescribes what it matches on a real
 *   benign input, not necessarily a false positive. The fix belongs in the rule: if
 *   case does not matter, add (?i) so the pattern says what it does; if it does,
 *   express the difference without letter case. This condition shape has no
 *   portable case-sensitive mode: a scoped (?-i:...) compiles only on Node 23+, and
 *   on the Node that CI pins, the engine drops the whole condition as a SyntaxError.
 *
 * RATCHET, FULL SET -- the same shape as gate-rule-status.ts and
 * gate-re2-portability.ts. Pre-existing findings live in
 * data/case-sensitivity-baseline.json as a count of affected conditions per rule,
 * and the whole working tree is compared against it, because rules also reach main
 * through doors no PR diff can see. Unlike those two, it runs on pull requests only
 * (the case-sensitivity job in rule-quality.yml), so a rule that reaches main
 * directly is caught by the next pull request that touches rules/, not at push.
 *
 * WHAT FAILS THE BUILD
 *   - A rule absent from the baseline has a finding.
 *   - A baselined rule has findings in more conditions than the baseline records.
 *   - A rule file the engine's loader cannot read. "Could not check" is never "clean".
 * WHAT DOES NOT
 *   - A baselined rule at or below its recorded count. Lower counts and fixed rules
 *     are listed so the baseline can be tightened with --write-baseline.
 *   - A condition the engine does not compile (invalid, or refused by its ReDoS
 *     check). The engine never evaluates it, so case cannot matter; it is counted,
 *     and validate-rules.ts owns that error.
 *
 * KNOWN GAPS (deliberate)
 *   - The baseline records how many conditions of a rule are affected, not which,
 *     as in gate-re2-portability.ts. Fixing one in a baselined rule while breaking
 *     another stays green. Recording condition indices or pattern text would churn
 *     on every reorder or cosmetic edit; the inflow this gate exists to stop is new
 *     rules, and the not-in-baseline check covers those completely.
 *   - Samples are matched as raw text, against every text on the test case's
 *     event rather than only the field the condition names. The engine reads one
 *     field (resolveField()), also tries the confusable-folded form, and skips a
 *     language-tagged condition when the input's language differs. So the gate
 *     can over-report, never under-report. None of it changed a verdict on
 *     2026-10-16 -- both findings are on the condition's own field, and no regex
 *     condition carries a language tag -- and modelling it would mean copying
 *     evaluateArrayCondition()'s pipeline here, the kind of copy this gate no
 *     longer keeps.
 *
 * EXIT CODES  0 pass · 1 an author must act · 2 the gate could not run.
 *
 * USAGE
 *   npx tsx scripts/gate-case-sensitivity.ts                    # gate
 *   npx tsx scripts/gate-case-sensitivity.ts --json             # machine-readable
 *   npx tsx scripts/gate-case-sensitivity.ts --write-baseline   # tighten only
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isReDoSSafe, regexConditionSpec, type RegexConditionSpec } from "../src/engine.js";
import { loadRuleFile } from "../src/loader.js";
import { buildEventFromTestCase } from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;

export const BASELINE_NOTE =
  "Rules with regex conditions that, read as written, keep one of the rule's own true_negatives " +
  "out only by letter case -- which src/engine.ts ignores: regexConditionSpec() compiles every " +
  "array-format regex condition with flag i. Values count affected conditions per rule. Ratchet " +
  "only -- entries may be lowered or removed as rules are fixed, never added or raised to silence " +
  "a new finding. See scripts/gate-case-sensitivity.ts.";

const MAX_LISTED = 20;
const EXCERPT = 100;

/** Thrown when the given flags or files cannot produce a meaningful run. */
export class CaseGateUsageError extends Error {}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface CaseGateOptions {
  readonly writeBaseline: boolean;
  readonly json: boolean;
}

export function parseCliOptions(argv: readonly string[]): CaseGateOptions {
  const known = new Set(["--write-baseline", "--json"]);
  const unknown = argv.filter((a) => a.startsWith("--") && !known.has(a));
  if (unknown.length > 0) throw new CaseGateUsageError(`unknown flag(s): ${unknown.join(", ")}`);
  return { writeBaseline: argv.includes("--write-baseline"), json: argv.includes("--json") };
}

// ---------------------------------------------------------------------------
// One condition, as the engine sees it and as it is written
// ---------------------------------------------------------------------------

export type ConditionView =
  | { readonly kind: "declared" }
  | { readonly kind: "uncompiled"; readonly reason: string }
  | { readonly kind: "compared"; readonly engine: RegExp; readonly written: RegExp };

/**
 * The regex the engine evaluates for a condition value, or null when the engine
 * refuses it -- regexConditionSpec() for source and flags, then the same two
 * refusals as safeCompile() in src/engine.ts.
 */
export function engineRegex(value: string): RegExp | null {
  const view = viewOf(regexConditionSpec(value));
  return view.kind === "compared" ? view.engine : null;
}

/** How a condition is compared: declared (?i), not compiled by the engine, or both readings. */
export function compileCondition(value: string): ConditionView {
  const spec = regexConditionSpec(value);
  return spec.inlineFlags.includes("i") ? { kind: "declared" } : viewOf(spec);
}

function viewOf(spec: RegexConditionSpec): ConditionView {
  if (!isReDoSSafe(spec.source)) {
    return { kind: "uncompiled", reason: "refused by the engine's ReDoS check" };
  }
  try {
    return {
      kind: "compared",
      engine: new RegExp(spec.source, spec.flags),
      written: new RegExp(spec.source, spec.flags.replace("i", "")),
    };
  } catch (err) {
    return { kind: "uncompiled", reason: `does not compile under /${spec.flags}: ${(err as Error).message}` };
  }
}

// ---------------------------------------------------------------------------
// Benign samples and findings
// ---------------------------------------------------------------------------

export interface BenignSample {
  /** Index in test_cases.true_negatives. */
  readonly index: number;
  /** Every distinct non-empty text on the event the rule's own test run builds for it. */
  readonly texts: readonly string[];
}

export function benignSamples(rule: ATRRule): readonly BenignSample[] {
  const negatives: unknown = rule.test_cases?.true_negatives;
  if (!Array.isArray(negatives)) return [];
  return negatives.map((entry: unknown, index) => {
    const tc =
      typeof entry === "string"
        ? { input: entry }
        : entry !== null && typeof entry === "object" && !Array.isArray(entry)
          ? (entry as Record<string, unknown>)
          : {};
    const event = buildEventFromTestCase(tc, rule);
    const texts = [event.content, ...Object.values(event.fields ?? {})].filter(
      (t): t is string => typeof t === "string" && t.length > 0,
    );
    return { index, texts: [...new Set(texts)] };
  });
}

export interface Finding {
  readonly ruleId: string;
  readonly file: string;
  /** Index in detection.conditions. */
  readonly condition: number;
  /** Index in test_cases.true_negatives. */
  readonly sample: number;
  /** The engine's flags for the condition. */
  readonly flags: string;
  /** What the engine matched in the sample, shortened. */
  readonly matched: string;
}

export interface Uncompiled {
  readonly ruleId: string;
  readonly file: string;
  readonly condition: number;
  readonly reason: string;
}

export interface RuleScan {
  readonly regexConditions: number;
  readonly declared: number;
  readonly compared: number;
  readonly uncompiled: readonly Uncompiled[];
  readonly findings: readonly Finding[];
}

function excerpt(text: string): string {
  const flat = text.replace(/\r?\n/g, "\\n");
  return flat.length > EXCERPT ? `${flat.slice(0, EXCERPT)}...` : flat;
}

/** Findings for one loaded rule. Pure apart from the engine's own pure helpers. */
export function scanRule(rule: ATRRule, file: string): RuleScan {
  const conditions: unknown = rule.detection?.conditions;
  const list: readonly unknown[] = Array.isArray(conditions) ? conditions : [];
  const samples = benignSamples(rule);
  const uncompiled: Uncompiled[] = [];
  const findings: Finding[] = [];
  let regexConditions = 0;
  let declared = 0;
  let compared = 0;

  list.forEach((raw, condition) => {
    const c = (raw ?? {}) as { operator?: unknown; value?: unknown };
    if (c.operator !== "regex" || typeof c.value !== "string") return;
    regexConditions++;
    const view = compileCondition(c.value);
    if (view.kind === "declared") {
      declared++;
      return;
    }
    if (view.kind === "uncompiled") {
      uncompiled.push({ ruleId: rule.id, file, condition, reason: view.reason });
      return;
    }
    compared++;
    for (const sample of samples) {
      const hit = sample.texts.find((t) => view.engine.test(t) && !view.written.test(t));
      if (hit === undefined) continue;
      const m = view.engine.exec(hit);
      findings.push({
        ruleId: rule.id,
        file,
        condition,
        sample: sample.index,
        flags: view.engine.flags,
        matched: excerpt(m ? m[0] : hit),
      });
    }
  });
  return { regexConditions, declared, compared, uncompiled, findings };
}

// ---------------------------------------------------------------------------
// Corpus scan
// ---------------------------------------------------------------------------

export interface RuleFindings {
  readonly ruleId: string;
  readonly file: string;
  /** Conditions with at least one finding -- the unit the baseline counts. */
  readonly conditions: number;
  readonly findings: readonly Finding[];
}

/** A file under rules/ the engine's loader refuses. Never a pass. */
export interface UnreadableRule {
  readonly file: string;
  readonly reason: string;
}

export interface CorpusScan {
  readonly rules: number;
  readonly regexConditions: number;
  readonly declared: number;
  readonly compared: number;
  readonly uncompiled: readonly Uncompiled[];
  readonly affected: ReadonlyMap<string, RuleFindings>;
  readonly unreadable: readonly UnreadableRule[];
}

/** Every *.yaml / *.yml under a directory tree, sorted for deterministic reports. */
export function listRuleFiles(dir: string): readonly string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .flatMap((entry) => {
      const p = join(dir, entry);
      const s = statSync(p);
      if (s.isDirectory()) return listRuleFiles(p);
      return s.isFile() && /\.ya?ml$/.test(entry) ? [p] : [];
    })
    .sort();
}

function groupByRule(findings: readonly Finding[]): ReadonlyMap<string, RuleFindings> {
  const byId = new Map<string, Finding[]>();
  for (const f of findings) byId.set(f.ruleId, [...(byId.get(f.ruleId) ?? []), f]);
  return new Map(
    [...byId].map(([ruleId, list]) => [
      ruleId,
      {
        ruleId,
        file: list[0]!.file,
        conditions: new Set(list.map((f) => `${f.file}#${f.condition}`)).size,
        findings: list,
      },
    ]),
  );
}

export function scanCorpus(rulesDir: string, repoRoot: string): CorpusScan {
  const unreadable: UnreadableRule[] = [];
  const scans: RuleScan[] = [];
  for (const abs of listRuleFiles(rulesDir)) {
    const file = relative(repoRoot, abs);
    let rule: ATRRule;
    try {
      rule = loadRuleFile(abs);
    } catch (err) {
      unreadable.push({ file, reason: (err as Error).message.split("\n")[0] ?? "unreadable" });
      continue;
    }
    // Outside the try: a crash while scanning is the gate failing to run (exit 2),
    // not a rule that could not be read.
    scans.push(scanRule(rule, file));
  }
  const sum = (pick: (s: RuleScan) => number): number => scans.reduce((n, s) => n + pick(s), 0);
  return {
    rules: scans.length,
    regexConditions: sum((s) => s.regexConditions),
    declared: sum((s) => s.declared),
    compared: sum((s) => s.compared),
    uncompiled: scans.flatMap((s) => s.uncompiled),
    affected: groupByRule(scans.flatMap((s) => s.findings)),
    unreadable,
  };
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

export interface CaseBaselineEntry {
  readonly conditions: number;
}

export interface CaseBaseline {
  readonly generatedAt: string;
  readonly note: string;
  readonly corpus: { readonly rules: number; readonly regexConditions: number };
  readonly knownCaseReliant: Readonly<Record<string, CaseBaselineEntry>>;
}

export const EMPTY_BASELINE: CaseBaseline = {
  generatedAt: "",
  note: BASELINE_NOTE,
  corpus: { rules: 0, regexConditions: 0 },
  knownCaseReliant: {},
};

/**
 * Parse and validate a baseline. A corrupt file must not read as empty (every
 * recorded rule would turn into a new failure) or as "anything goes" (the gate
 * would become a no-op), so the shape is checked rather than trusted.
 */
export function parseBaseline(raw: string, source: string): CaseBaseline {
  let doc: Partial<CaseBaseline> | null;
  try {
    doc = JSON.parse(raw) as Partial<CaseBaseline> | null;
  } catch (err) {
    throw new CaseGateUsageError(`${source}: not valid JSON -- ${(err as Error).message}`);
  }
  const known: unknown = doc?.knownCaseReliant;
  if (known === null || typeof known !== "object" || Array.isArray(known)) {
    throw new CaseGateUsageError(`${source}: "knownCaseReliant" must be an object of ruleId -> {conditions}`);
  }
  for (const [id, entry] of Object.entries(known as Record<string, unknown>)) {
    const n = (entry as { conditions?: unknown } | null)?.conditions;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1) {
      throw new CaseGateUsageError(`${source}: entry "${id}" needs {conditions: <positive integer>}`);
    }
  }
  return { ...EMPTY_BASELINE, ...doc, knownCaseReliant: known as Record<string, CaseBaselineEntry> };
}

export function loadBaseline(path: string): CaseBaseline {
  if (!existsSync(path)) return EMPTY_BASELINE;
  return parseBaseline(readFileSync(path, "utf-8"), path);
}

/**
 * Tighten-only update: fixed rules drop out and improved counts come down, and
 * nothing is ever added or raised. Widening is the one move that would make this
 * gate lie, so it is not automatable -- a genuine new exception has to be written
 * into the file by hand, where CODEOWNERS review sees it.
 */
export function tightenBaseline(baseline: CaseBaseline, scan: CorpusScan, now: string): CaseBaseline {
  const kept = Object.entries(baseline.knownCaseReliant)
    .flatMap(([id, entry]): Array<[string, CaseBaselineEntry]> => {
      const current = scan.affected.get(id);
      return current ? [[id, { conditions: Math.min(entry.conditions, current.conditions) }]] : [];
    })
    .sort(([a], [b]) => a.localeCompare(b));
  return {
    generatedAt: now,
    note: BASELINE_NOTE,
    corpus: { rules: scan.rules, regexConditions: scan.regexConditions },
    knownCaseReliant: Object.fromEntries(kept),
  };
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

export interface Regression {
  readonly rule: RuleFindings;
  readonly recorded: number;
}

export interface CaseComparison {
  /** Rules with findings and no baseline entry. These fail the build. */
  readonly added: readonly RuleFindings[];
  /** Baselined rules with findings in more conditions than recorded. These fail too. */
  readonly worsened: readonly Regression[];
  /** Baselined rules with fewer affected conditions than recorded. Tighten these. */
  readonly improved: readonly string[];
  /** Baselined rules with no finding left (fixed, or gone). Tighten these. */
  readonly resolved: readonly string[];
}

/** A baseline entry by rule id, own keys only -- "constructor" is not a baselined rule. */
function recorded(baseline: CaseBaseline, ruleId: string): CaseBaselineEntry | undefined {
  return Object.hasOwn(baseline.knownCaseReliant, ruleId) ? baseline.knownCaseReliant[ruleId] : undefined;
}

export function compareToBaseline(scan: CorpusScan, baseline: CaseBaseline): CaseComparison {
  const known = baseline.knownCaseReliant;
  const current = [...scan.affected.values()];
  const ids = Object.keys(known).sort();
  return {
    added: current.filter((r) => recorded(baseline, r.ruleId) === undefined),
    worsened: current.flatMap((r) => {
      const entry = recorded(baseline, r.ruleId);
      return entry && r.conditions > entry.conditions ? [{ rule: r, recorded: entry.conditions }] : [];
    }),
    improved: ids.filter((id) => {
      const r = scan.affected.get(id);
      return r !== undefined && r.conditions < known[id]!.conditions;
    }),
    resolved: ids.filter((id) => !scan.affected.has(id)),
  };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/** One line per affected condition: where it is and what the engine let in. */
function renderRule(rule: RuleFindings, label: string): string[] {
  const firstPerCondition = rule.findings.filter(
    (f, i) => rule.findings.findIndex((g) => g.condition === f.condition) === i,
  );
  return [
    label ? `  - ${rule.ruleId}  ${label}` : `  - ${rule.ruleId}`,
    `      ${rule.file}`,
    ...firstPerCondition.map(
      (f) =>
        `      condition[${f.condition}] /${f.flags} matches true_negatives[${f.sample}], ` +
        `as written it does not: "${f.matched}"`,
    ),
  ];
}

const FIX_HINT = [
  "src/engine.ts regexConditionSpec() compiles every array-format regex condition with",
  "flag i, whether or not the pattern says (?i), so letter case keeps nothing out. For",
  "each condition above:",
  "  - if case does not matter, start the pattern with (?i) so it says what it does;",
  "  - if it does, express the difference without letter case (surrounding syntax, a",
  "    delimiter, another condition). There is no portable case-sensitive mode: a",
  "    scoped (?-i:...) compiles only on Node 23+, and older runtimes drop the condition.",
  "Do NOT add the rule to data/case-sensitivity-baseline.json to silence this.",
];

function renderReport(scan: CorpusScan, baseline: CaseBaseline, c: CaseComparison): string[] {
  const findings = [...scan.affected.values()];
  const conditions = findings.reduce((n, r) => n + r.conditions, 0);
  const out = [
    "",
    "=== ATR Case Sensitivity GATE ===",
    `corpus: ${scan.rules} rules, ${scan.regexConditions} regex conditions -- ${scan.declared} declare (?i), ` +
      `${scan.compared} compared against their rule's true_negatives, ${scan.uncompiled.length} not compiled by the engine`,
    `case-reliant: ${conditions} condition(s) in ${findings.length} rule(s); ` +
      `baseline records ${Object.keys(baseline.knownCaseReliant).length} rule(s)`,
  ];
  if (scan.unreadable.length > 0) {
    out.push("", `GATE FAIL -- ${scan.unreadable.length} rule file(s) could not be loaded, so they were not checked:`);
    out.push(...scan.unreadable.slice(0, MAX_LISTED).map((u) => `  - ${u.file}: ${u.reason}`));
  }
  if (c.added.length > 0 || c.worsened.length > 0) {
    out.push("", "GATE FAIL -- condition(s) that keep a benign sample out only by letter case, which the engine ignores:");
    out.push(...c.added.flatMap((r) => renderRule(r, "(not in baseline)")));
    out.push(...c.worsened.flatMap((w) => renderRule(w.rule, `(${w.recorded} -> ${w.rule.conditions} conditions)`)));
    out.push("", ...FIX_HINT);
  }
  const debt = findings.filter((r) => recorded(baseline, r.ruleId) !== undefined);
  if (debt.length > 0) {
    out.push("", `ACCEPTED DEBT -- ${debt.length} baselined rule(s), still case-reliant:`);
    out.push(...debt.slice(0, MAX_LISTED).flatMap((r) => renderRule(r, "")));
  }
  if (c.improved.length > 0 || c.resolved.length > 0) {
    out.push("", "RATCHET -- these improved and should be tightened in the baseline:");
    out.push(...c.resolved.map((id) => `  + ${id}: no case-reliant condition left`));
    out.push(...c.improved.map((id) => `  + ${id}: fewer case-reliant conditions than recorded`));
    out.push("  (run: npx tsx scripts/gate-case-sensitivity.ts --write-baseline)");
  }
  if (scan.uncompiled.length > 0) {
    out.push(
      "",
      `note: ${scan.uncompiled.length} condition(s) are not compiled by the engine (invalid, or refused by its`,
      "ReDoS check) and were not compared. The engine never evaluates them; validate-rules.ts owns that error.",
    );
  }
  return out;
}

function renderJson(scan: CorpusScan, c: CaseComparison): string {
  return JSON.stringify(
    {
      rules: scan.rules,
      regexConditions: scan.regexConditions,
      declared: scan.declared,
      compared: scan.compared,
      uncompiled: scan.uncompiled,
      unreadable: scan.unreadable,
      findings: [...scan.affected.values()].flatMap((r) => r.findings),
      added: c.added.map((r) => r.ruleId),
      worsened: c.worsened.map((w) => ({ ruleId: w.rule.ruleId, recorded: w.recorded, now: w.rule.conditions })),
      improved: c.improved,
      resolved: c.resolved,
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

export interface CaseGateDeps {
  readonly repoRoot: string;
  readonly rulesDir: string;
  readonly baselinePath: string;
  readonly now: () => string;
}

export function defaultDeps(): CaseGateDeps {
  return {
    repoRoot: REPO_ROOT,
    rulesDir: join(REPO_ROOT, "rules"),
    baselinePath: join(REPO_ROOT, "data/case-sensitivity-baseline.json"),
    now: () => new Date().toISOString(),
  };
}

export interface GateResult {
  readonly code: number;
  readonly lines: readonly string[];
  readonly comparison: CaseComparison;
}

function writeTightened(baseline: CaseBaseline, scan: CorpusScan, c: CaseComparison, deps: CaseGateDeps): GateResult {
  const next = tightenBaseline(baseline, scan, deps.now());
  writeFileSync(deps.baselinePath, `${JSON.stringify(next, null, 2)}\n`, "utf-8");
  const before = Object.keys(baseline.knownCaseReliant).length;
  const after = Object.keys(next.knownCaseReliant).length;
  const lines = [`[case-gate] baseline tightened: ${before} -> ${after} rule(s)`];
  const refused = [...c.added, ...c.worsened.map((w) => w.rule)];
  if (refused.length > 0) {
    lines.push(
      `[case-gate] ${refused.length} rule(s) with new or worse findings were NOT added --`,
      "            --write-baseline only shrinks. Fix those rules instead:",
      ...refused.map((r) => `  - ${r.ruleId}  ${r.file}`),
    );
  }
  return { code: EXIT_OK, lines, comparison: c };
}

export function runGate(options: CaseGateOptions, deps: CaseGateDeps = defaultDeps()): GateResult {
  const baseline = loadBaseline(deps.baselinePath);
  const scan = scanCorpus(deps.rulesDir, deps.repoRoot);
  if (scan.rules === 0 && scan.unreadable.length === 0) {
    // A wrong path must not read as a clean corpus.
    throw new CaseGateUsageError(`no rule files under ${deps.rulesDir} -- refusing to report a pass over nothing`);
  }
  const comparison = compareToBaseline(scan, baseline);
  if (options.writeBaseline) {
    if (scan.unreadable.length > 0) {
      // A rule the scan could not read would drop out of the baseline as if fixed.
      return {
        code: EXIT_FAIL,
        lines: [
          `[case-gate] baseline NOT written: ${scan.unreadable.length} rule file(s) could not be loaded,`,
          "            and an unchecked rule is not a fixed one:",
          ...scan.unreadable.map((u) => `  - ${u.file}: ${u.reason}`),
        ],
        comparison,
      };
    }
    return writeTightened(baseline, scan, comparison, deps);
  }

  const failed =
    scan.unreadable.length > 0 || comparison.added.length > 0 || comparison.worsened.length > 0;
  const code = failed ? EXIT_FAIL : EXIT_OK;
  if (options.json) return { code, lines: [renderJson(scan, comparison)], comparison };
  const verdict = failed ? [] : ["", "GATE PASS -- no new condition relies on a letter-case distinction the engine ignores."];
  return { code, lines: [...renderReport(scan, baseline, comparison), ...verdict, ""], comparison };
}

export function main(argv: readonly string[], deps: CaseGateDeps = defaultDeps()): number {
  try {
    const { code, lines } = runGate(parseCliOptions(argv), deps);
    console.log(lines.join("\n"));
    return code;
  } catch (err) {
    // Exit 2 is "the gate could not run" -- never conflated with a verdict.
    const detail = err instanceof CaseGateUsageError ? err.message : String((err as Error).stack ?? err);
    console.error(`[case-gate] could not run: ${detail}`);
    return EXIT_USAGE;
  }
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
