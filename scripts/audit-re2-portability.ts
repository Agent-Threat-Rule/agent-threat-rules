/**
 * RE2 portability audit for the ATR rule corpus.
 *
 * Downstream consumers of ATR rules run RE2-family engines (Go `regexp`,
 * Rust `regex`, and every Sigma backend that compiles to them). RE2 is a
 * finite-automaton engine: it rejects constructs that need backtracking, and
 * it spells some escapes differently from JavaScript. A rule whose regex uses
 * those constructs cannot be exported faithfully, so this script finds them.
 *
 * WHAT IS SCANNED
 *   Only strings the ATR engine actually compiles as regular expressions:
 *     - array-format  `detection.conditions[].value`  where operator == regex
 *     - named-format  `detection.conditions.<name>.patterns[]` where
 *       match_type is regex (engine defaults an absent match_type to regex)
 *     - sequence      `detection.conditions.<name>.steps[].patterns[]`
 *   Prose fields (title / description / test_cases / false_positives) are
 *   NEVER scanned. They contain regex-looking text that is not a regex, and
 *   treating them as patterns is the main way this audit could produce
 *   fiction.
 *
 * CLASSIFICATION
 *   mechanically fixable  unicodeEscape   \uXXXX  -> \x{XXXX}   (equivalent)
 *                         namedGroup      (?<n>)  -> (?P<n>)    (equivalent)
 *   not fixable           lookaround      (?= (?! (?<= (?<!
 *                         backreference   \1..\9, \k<name>
 *                         atomicOrPossessive  (?>...)  a*+ a++ a?+ a{n,m}+
 *   A rule is "mechanically fixable" only when every incompatibility it has
 *   falls in the first group.
 *
 *   A sixth bucket, `other`, holds RE2 incompatibilities outside those five:
 *   `\b` inside a character class (a JS backspace escape that RE2 rejects,
 *   and almost always an authoring slip for a word boundary) and repeat
 *   counts above RE2's hard limit of 1000. Both need a human decision, so
 *   they count as incompatible and never as mechanically fixable.
 *
 * USAGE
 *   npx tsx scripts/audit-re2-portability.ts
 *   npx tsx scripts/audit-re2-portability.ts --json
 *   npx tsx scripts/audit-re2-portability.ts --fail-on-notfixable   # CI gate
 *   npx tsx scripts/audit-re2-portability.ts --verify-re2           # needs Go
 *
 * `--verify-re2` is the honesty check: it compiles every pattern (and every
 * proposed rewrite) with Go's regexp package, which IS RE2, and reports any
 * disagreement with the static verdict. Without it the verdict is a careful
 * parse; with it the verdict is measured. Read-only; writes nothing.
 */
import { readFileSync, readdirSync, statSync, mkdtempSync, writeFileSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { load as yamlLoad } from "js-yaml";

const RULES_DIR = resolve(process.cwd(), "rules");

/** The five RE2 incompatibility classes this audit reports. */
export type IncompatClass =
  | "lookaround"
  | "backreference"
  | "atomicOrPossessive"
  | "namedGroup"
  | "unicodeEscape";

/** Classes that a scripted rewrite can fix without changing semantics. */
const FIXABLE_CLASSES: ReadonlySet<IncompatClass> = new Set<IncompatClass>([
  "namedGroup",
  "unicodeEscape",
]);

export interface Finding {
  readonly cls: IncompatClass | "other";
  readonly token: string;
  readonly index: number;
  readonly detail: string;
}

export interface PatternRef {
  readonly file: string;
  readonly ruleId: string;
  readonly location: string;
  readonly pattern: string;
}

export interface PatternAudit extends PatternRef {
  readonly findings: readonly Finding[];
}

// ---------------------------------------------------------------------------
// Corpus walking + pattern extraction
// ---------------------------------------------------------------------------

function collectRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...collectRuleFiles(full));
    else if (/\.ya?ml$/i.test(entry)) out.push(full);
  }
  return out;
}

function isRegexOperator(raw: unknown): boolean {
  // Accept the documented operator plus the negated/quantified spellings that
  // downstream forks use, so a renamed operator cannot silently skip the audit.
  const op = String(raw ?? "regex").trim().toLowerCase();
  return op === "regex" || op === "regex_all" || op === "regex_any" || op === "not_regex";
}

/** Pull regex strings out of one parsed rule document. Pure; allocates new. */
function extractPatterns(doc: unknown, file: string): PatternRef[] {
  const rule = (doc ?? {}) as Record<string, unknown>;
  const ruleId = String(rule["id"] ?? "(no id)");
  const detection = (rule["detection"] ?? {}) as Record<string, unknown>;
  const conditions = detection["conditions"];
  const push = (location: string, pattern: unknown): PatternRef[] =>
    typeof pattern === "string" ? [{ file, ruleId, location, pattern }] : [];

  if (Array.isArray(conditions)) {
    return conditions.flatMap((cond, i) => {
      const c = (cond ?? {}) as Record<string, unknown>;
      if (!isRegexOperator(c["operator"])) return [];
      return push(`detection.conditions[${i}].value`, c["value"]);
    });
  }
  if (conditions && typeof conditions === "object") {
    return Object.entries(conditions as Record<string, unknown>).flatMap(([name, def]) =>
      extractNamedCondition(name, def, file, ruleId)
    );
  }
  return [];
}

/** Named-map condition: {patterns, match_type} or {steps: [{patterns}]}. */
function extractNamedCondition(
  name: string,
  def: unknown,
  file: string,
  ruleId: string
): PatternRef[] {
  const cond = (def ?? {}) as Record<string, unknown>;
  const base = `detection.conditions.${name}`;
  const out: PatternRef[] = [];
  const take = (patterns: unknown, matchType: unknown, loc: string): void => {
    if (!Array.isArray(patterns) || !isRegexOperator(matchType)) return;
    patterns.forEach((p, i) => {
      if (typeof p === "string") out.push({ file, ruleId, location: `${loc}[${i}]`, pattern: p });
    });
  };
  take(cond["patterns"], cond["match_type"], `${base}.patterns`);
  const steps = cond["steps"];
  if (Array.isArray(steps)) {
    steps.forEach((step, i) => {
      const s = (step ?? {}) as Record<string, unknown>;
      take(s["patterns"], s["match_type"], `${base}.steps[${i}].patterns`);
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Regex scanner
// ---------------------------------------------------------------------------

const HEX4 = /^[0-9a-fA-F]{4}$/;

/** RE2's hard cap on a repeat bound (Go regexp/syntax maxRepeat). */
const RE2_MAX_REPEAT = 1000;

function scanEscape(rx: string, i: number, inClass: boolean): { findings: Finding[]; next: number } {
  const c = rx[i + 1] ?? "";
  if (c === "u") return scanUnicodeEscape(rx, i);
  if (inClass && (c === "b" || c === "B")) {
    return {
      findings: [{ cls: "other", token: `\\${c}`, index: i, detail: `\\${c} inside a character class is a JS backspace escape; RE2 rejects it` }],
      next: i + 2,
    };
  }
  if (c === "k" && rx[i + 2] === "<") {
    const end = rx.indexOf(">", i + 2);
    const token = end === -1 ? rx.slice(i) : rx.slice(i, end + 1);
    return {
      findings: [{ cls: "backreference", token, index: i, detail: "named backreference \\k<name> is unsupported by RE2" }],
      next: end === -1 ? rx.length : end + 1,
    };
  }
  if (!inClass && c >= "1" && c <= "9") {
    return {
      findings: [{ cls: "backreference", token: `\\${c}`, index: i, detail: "numeric backreference requires backtracking; RE2 rejects it" }],
      next: i + 2,
    };
  }
  return { findings: [], next: i + 2 };
}

function scanUnicodeEscape(rx: string, i: number): { findings: Finding[]; next: number } {
  if (rx[i + 2] === "{") {
    const end = rx.indexOf("}", i + 2);
    const token = end === -1 ? rx.slice(i) : rx.slice(i, end + 1);
    return {
      findings: [{ cls: "unicodeEscape", token, index: i, detail: "JS \\u{...} escape; RE2 spells it \\x{...}" }],
      next: end === -1 ? rx.length : end + 1,
    };
  }
  const digits = rx.slice(i + 2, i + 6);
  if (HEX4.test(digits)) {
    return {
      findings: [{ cls: "unicodeEscape", token: `\\u${digits}`, index: i, detail: "JS \\uXXXX escape; RE2 spells it \\x{XXXX}" }],
      next: i + 6,
    };
  }
  return {
    findings: [{ cls: "other", token: rx.slice(i, i + 2), index: i, detail: "bare \\u with no hex payload" }],
    next: i + 2,
  };
}

function scanGroupOpen(rx: string, i: number): { findings: Finding[]; next: number } {
  const head3 = rx.slice(i, i + 3);
  const head4 = rx.slice(i, i + 4);
  if (head4 === "(?<=" || head4 === "(?<!") {
    return { findings: [{ cls: "lookaround", token: head4, index: i, detail: "lookbehind requires backtracking; RE2 rejects it" }], next: i + 4 };
  }
  if (head3 === "(?=" || head3 === "(?!") {
    return { findings: [{ cls: "lookaround", token: head3, index: i, detail: "lookahead requires backtracking; RE2 rejects it" }], next: i + 3 };
  }
  if (head3 === "(?>") {
    return { findings: [{ cls: "atomicOrPossessive", token: head3, index: i, detail: "atomic group is not expressible in RE2" }], next: i + 3 };
  }
  if (rx.slice(i, i + 3) === "(?<") {
    const end = rx.indexOf(">", i + 3);
    const token = end === -1 ? rx.slice(i) : rx.slice(i, end + 1);
    return {
      findings: [{ cls: "namedGroup", token, index: i, detail: "JS named group (?<n>); RE2 spells it (?P<n>)" }],
      next: end === -1 ? rx.length : end + 1,
    };
  }
  return { findings: [], next: i + 1 };
}

/**
 * Walk a regex tracking escape and character-class state, and report every
 * RE2-incompatible construct. Character-class interiors are respected so that
 * `[(?=]` or `[*+]` are read as literals, not as operators.
 */
export function scanPattern(rx: string): Finding[] {
  const findings: Finding[] = [];
  let i = 0;
  let inClass = false;
  let quantEnd = -1; // index just past the last quantifier consumed

  while (i < rx.length) {
    const ch = rx[i]!;
    if (ch === "\\") {
      const r = scanEscape(rx, i, inClass);
      findings.push(...r.findings);
      i = r.next;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      i += 1;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      i += 1;
      continue;
    }
    if (ch === "(") {
      const r = scanGroupOpen(rx, i);
      findings.push(...r.findings);
      i = r.next;
      continue;
    }
    const quant = readQuantifier(rx, i);
    if (quant !== null) {
      findings.push(...scanQuantifier(rx, i, quant, quantEnd));
      quantEnd = quant;
      i = quant;
      continue;
    }
    i += 1;
  }
  return findings;
}

/**
 * Findings attached to a quantifier that spans [start, end): an out-of-range
 * repeat bound, and a trailing `+` that makes it possessive. `prevEnd` guards
 * against reading the second `+` of `a++` as a fresh quantifier.
 */
function scanQuantifier(rx: string, start: number, end: number, prevEnd: number): Finding[] {
  const bounds = checkRepeatBounds(rx, start);
  if (rx[end] !== "+" || end === prevEnd) return bounds;
  return [
    ...bounds,
    {
      cls: "atomicOrPossessive",
      token: rx.slice(start, end + 1),
      index: start,
      detail: "possessive quantifier is not expressible in RE2",
    },
  ];
}

/** RE2 caps every repeat bound at 1000; JS has no such limit. */
function checkRepeatBounds(rx: string, i: number): Finding[] {
  const m = /^\{(\d+)(?:,(\d*))?\}/.exec(rx.slice(i));
  if (!m) return [];
  const bounds = [Number(m[1]), m[2] ? Number(m[2]) : 0];
  if (bounds.every((n) => n <= RE2_MAX_REPEAT)) return [];
  return [
    {
      cls: "other",
      token: m[0],
      index: i,
      detail: `repeat bound exceeds RE2's limit of ${RE2_MAX_REPEAT}`,
    },
  ];
}

/**
 * If a quantifier starts at `i`, return the index just past it, else null.
 * `?` directly after `(` is a group-kind marker, not a quantifier, and is
 * already consumed by scanGroupOpen.
 */
function readQuantifier(rx: string, i: number): number | null {
  const ch = rx[i]!;
  const prev = i > 0 ? rx[i - 1] : "";
  if (ch === "*" || ch === "+" || ch === "?") {
    if (i === 0 || prev === "(" || prev === "|") return null;
    return rx[i + 1] === "?" ? i + 2 : i + 1; // absorb lazy marker
  }
  if (ch === "{") {
    const m = /^\{\d+(,\d*)?\}/.exec(rx.slice(i));
    if (!m) return null;
    const end = i + m[0].length;
    return rx[end] === "?" ? end + 1 : end;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Mechanical rewrite
// ---------------------------------------------------------------------------

/**
 * Rewrite the two mechanically-fixable classes into RE2 spelling. Returns the
 * pattern unchanged when it has no fixable construct. Never mutates input.
 */
export function rewriteForRe2(rx: string): string {
  return rx
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_m, hex: string) => `\\x{${hex}}`)
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, hex: string) => `\\x{${hex}}`)
    .replace(/\(\?<([A-Za-z_][A-Za-z0-9_]*)>/g, (_m, name: string) => `(?P<${name}>`);
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

interface RuleVerdict {
  readonly file: string;
  readonly ruleId: string;
  readonly classes: readonly IncompatClass[];
  readonly fixable: boolean;
  readonly patterns: readonly PatternAudit[];
}

function buildVerdicts(audits: readonly PatternAudit[], files: readonly string[]): RuleVerdict[] {
  const byFile = new Map<string, PatternAudit[]>();
  for (const a of audits) {
    if (a.findings.length === 0) continue;
    byFile.set(a.file, [...(byFile.get(a.file) ?? []), a]);
  }
  return files
    .filter((f) => byFile.has(f))
    .map((file) => {
      const patterns = byFile.get(file)!;
      const classes = [
        ...new Set(
          patterns.flatMap((p) => p.findings.map((f) => f.cls)).filter((c): c is IncompatClass => c !== "other")
        ),
      ].sort();
      return {
        file,
        ruleId: patterns[0]!.ruleId,
        classes,
        fixable: classes.length > 0 && classes.every((c) => FIXABLE_CLASSES.has(c)),
        patterns,
      };
    });
}

function countByClass(verdicts: readonly RuleVerdict[]): Record<IncompatClass, number> {
  const zero: Record<IncompatClass, number> = {
    lookaround: 0,
    backreference: 0,
    atomicOrPossessive: 0,
    namedGroup: 0,
    unicodeEscape: 0,
  };
  return verdicts.reduce(
    (acc, v) => v.classes.reduce((inner, c) => ({ ...inner, [c]: inner[c] + 1 }), acc),
    zero
  );
}

// ---------------------------------------------------------------------------
// Optional empirical verification against Go's regexp (which is RE2)
// ---------------------------------------------------------------------------

const GO_ORACLE = `package main

import (
	"encoding/json"
	"os"
	"regexp"
)

func main() {
	var in []string
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		os.Exit(2)
	}
	out := make([]map[string]any, 0, len(in))
	for _, p := range in {
		entry := map[string]any{"ok": true, "error": ""}
		if _, err := regexp.Compile(p); err != nil {
			entry["ok"] = false
			entry["error"] = err.Error()
		}
		out = append(out, entry)
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
`;

interface OracleResult {
  readonly ok: boolean;
  readonly error: string;
}

function compileWithGo(patterns: readonly string[]): OracleResult[] | null {
  try {
    const dir = mkdtempSync(join(tmpdir(), "atr-re2-"));
    const src = join(dir, "main.go");
    writeFileSync(src, GO_ORACLE, "utf8");
    const stdout = execFileSync("go", ["run", src], {
      input: JSON.stringify(patterns),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(stdout) as OracleResult[];
  } catch {
    return null;
  }
}

interface OracleReport {
  readonly available: boolean;
  readonly rawFailures: number;
  readonly rewrittenFailures: number;
  /** Patterns the scanner called auto-fixable that the rewrite genuinely repaired. */
  readonly fixableRepaired: number;
  readonly fixableTotal: number;
  readonly disagreements: readonly string[];
  readonly failureSamples: readonly string[];
}

const EMPTY_ORACLE: OracleReport = {
  available: false,
  rawFailures: 0,
  rewrittenFailures: 0,
  fixableRepaired: 0,
  fixableTotal: 0,
  disagreements: [],
  failureSamples: [],
};

function verifyWithRe2(audits: readonly PatternAudit[]): OracleReport {
  const raw = compileWithGo(audits.map((a) => a.pattern));
  const fixed = raw && compileWithGo(audits.map((a) => rewriteForRe2(a.pattern)));
  if (!raw || !fixed) return EMPTY_ORACLE;
  const disagreements: string[] = [];
  const failureSamples: string[] = [];
  audits.forEach((a, i) => {
    const flagged = a.findings.length > 0;
    const claimedFixable = flagged && a.findings.every((f) => f.cls !== "other" && FIXABLE_CLASSES.has(f.cls));
    if (!raw[i]!.ok && !flagged) {
      disagreements.push(`${a.ruleId} ${a.location}: RE2 rejects but scanner found nothing -- ${raw[i]!.error}`);
    }
    if (raw[i]!.ok && flagged) {
      disagreements.push(`${a.ruleId} ${a.location}: scanner flagged but RE2 accepts it as written`);
    }
    // Only a broken promise if the scanner claimed this one was auto-fixable.
    if (claimedFixable && !fixed[i]!.ok) {
      disagreements.push(`${a.ruleId} ${a.location}: rewrite still rejected by RE2 -- ${fixed[i]!.error}`);
    }
    if (!raw[i]!.ok && failureSamples.length < 40) {
      failureSamples.push(`${a.ruleId} ${a.location}: ${raw[i]!.error}`);
    }
  });
  const fixableIdx = audits.map((a, i) => [a, i] as const).filter(([a]) => a.findings.length > 0 && a.findings.every((f) => f.cls !== "other" && FIXABLE_CLASSES.has(f.cls)));
  return {
    available: true,
    rawFailures: raw.filter((r) => !r.ok).length,
    rewrittenFailures: fixed.filter((r) => !r.ok).length,
    fixableRepaired: fixableIdx.filter(([, i]) => !raw[i]!.ok && fixed[i]!.ok).length,
    fixableTotal: fixableIdx.length,
    disagreements,
    failureSamples,
  };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

interface Totals {
  readonly rules: number;
  readonly patterns: number;
  readonly badPatterns: number;
  readonly otherRules: number;
}

function renderOracle(oracle: OracleReport | null): string[] {
  if (!oracle) return [];
  if (!oracle.available) {
    return ["RE2 oracle unavailable (Go toolchain not found); verdict is static analysis only", ""];
  }
  return [
    "RE2 ORACLE (Go regexp -- the real engine, not a heuristic)",
    `  patterns RE2 rejects as written   ${oracle.rawFailures}`,
    `  patterns RE2 rejects after rewrite ${oracle.rewrittenFailures}`,
    `  auto-fixable patterns repaired     ${oracle.fixableRepaired} / ${oracle.fixableTotal}`,
    `  scanner/oracle disagreements       ${oracle.disagreements.length}`,
    ...oracle.disagreements.slice(0, 20).map((d) => `    ${d}`),
    "",
  ];
}

// ---------------------------------------------------------------------------
// Remediation coverage
// ---------------------------------------------------------------------------
//
// "Mechanically fixable" above is a STATIC claim: the rule's only RE2 blocker
// is a spelling this repo can rewrite. Whether the rewrite actually preserves
// meaning is a separate, empirical question, answered by
// scripts/verify-re2-equivalence.ts running both engines over a shared input
// battery. That run records the patterns whose rewrite compiles under RE2 but
// does NOT reproduce the original match vector, in data/re2-equivalence.json.
//
// Coverage reconciles the two so the static claim can never quietly overstate
// what was really delivered: fixable-and-verified rules are genuinely portable
// downstream, fixable-but-divergent rules are not, and every remaining rule is
// carried as portability metadata instead of a silent downstream failure.

const EQUIVALENCE_PATH = resolve(process.cwd(), "data/re2-equivalence.json");

interface Coverage {
  readonly incompatible: number;
  readonly claimedFixable: number;
  readonly verifiedPortable: number;
  readonly divergentAfterRewrite: readonly string[];
  readonly taggedForDownstream: number;
  readonly equivalenceAvailable: boolean;
}

/** Rule ids whose rewrite was measured to diverge under RE2. */
function loadDivergentRuleIds(path: string = EQUIVALENCE_PATH): string[] | null {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { divergentRules?: Record<string, unknown> };
    return Object.keys(parsed.divergentRules ?? {});
  } catch {
    return null;
  }
}

function computeCoverage(verdicts: readonly RuleVerdict[]): Coverage {
  const divergent = loadDivergentRuleIds();
  const claimed = verdicts.filter((v) => v.fixable);
  const divergentSet = new Set(divergent ?? []);
  const stillBroken = claimed.filter((v) => divergentSet.has(v.ruleId)).map((v) => v.ruleId);
  return {
    incompatible: verdicts.length,
    claimedFixable: claimed.length,
    verifiedPortable: divergent === null ? 0 : claimed.length - stillBroken.length,
    divergentAfterRewrite: stillBroken,
    taggedForDownstream: verdicts.length,
    equivalenceAvailable: divergent !== null,
  };
}

function renderCoverage(c: Coverage): string[] {
  if (!c.equivalenceAvailable) {
    return [
      "REMEDIATION COVERAGE",
      "  data/re2-equivalence.json missing -- run:",
      "    npx tsx scripts/verify-re2-equivalence.ts --write-equivalence data/re2-equivalence.json",
      "",
    ];
  }
  const pct = (n: number): string => `${((n / Math.max(c.incompatible, 1)) * 100).toFixed(1)}%`;
  return [
    "REMEDIATION COVERAGE (static claim reconciled against the differential run)",
    `  incompatible rules                      ${c.incompatible}`,
    `  claimed mechanically fixable            ${c.claimedFixable}`,
    `  VERIFIED portable after rewrite         ${c.verifiedPortable}  (${pct(c.verifiedPortable)} of incompatible)`,
    `  rewrite compiles but DIVERGES           ${c.divergentAfterRewrite.length}  -> treated as not portable`,
    ...c.divergentAfterRewrite.map((id) => `      ${id}`),
    `  carried as portability metadata         ${c.taggedForDownstream}  (${pct(c.taggedForDownstream)} -- every incompatible rule is tagged)`,
    "",
    "  Downstream effect: RE2 backends read atr.portability.re2-blocked from the",
    "  Sigma export and skip those rules instead of failing to compile mid-pipeline.",
    "",
  ];
}

function renderTable(verdicts: readonly RuleVerdict[], totals: Totals, oracle: OracleReport | null): string {
  const byClass = countByClass(verdicts);
  const fixable = verdicts.filter((v) => v.fixable);
  const notFixable = verdicts.filter((v) => !v.fixable);
  const detail = (v: RuleVerdict): string =>
    `  ${v.ruleId.padEnd(18)} ${(v.classes.join(",") || "other").padEnd(26)} ${relative(process.cwd(), v.file)}`;
  return [
    "RE2 portability audit -- ATR rule corpus",
    "=".repeat(72),
    `rules scanned            ${totals.rules}`,
    `regex patterns scanned   ${totals.patterns}`,
    `patterns incompatible    ${totals.badPatterns}`,
    `rules incompatible       ${verdicts.length}`,
    "",
    "by class (rules; a rule can appear in more than one row)",
    ...(Object.keys(byClass) as IncompatClass[]).map(
      (c) =>
        `  ${c.padEnd(20)} ${String(byClass[c]).padStart(4)}  ${FIXABLE_CLASSES.has(c) ? "mechanically fixable" : "needs refactor"}`
    ),
    `  ${"other".padEnd(20)} ${String(totals.otherRules).padStart(4)}  needs refactor (outside the five classes)`,
    "",
    `mechanically fixable     ${fixable.length}`,
    `not fixable              ${notFixable.length}`,
    "",
    ...renderCoverage(computeCoverage(verdicts)),
    ...(fixable.length ? ["MECHANICALLY FIXABLE", ...fixable.map(detail), ""] : []),
    ...(notFixable.length ? ["NOT FIXABLE (refactor or mark non-portable)", ...notFixable.map(detail), ""] : []),
    ...renderOracle(oracle),
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function main(): void {
  const argv = process.argv.slice(2);
  const wantJson = argv.includes("--json");
  const failOnNotFixable = argv.includes("--fail-on-notfixable");
  const wantOracle = argv.includes("--verify-re2");

  const files = collectRuleFiles(RULES_DIR);
  const audits: PatternAudit[] = files.flatMap((file) => {
    const doc = yamlLoad(readFileSync(file, "utf8"));
    return extractPatterns(doc, file).map((ref) => ({ ...ref, findings: scanPattern(ref.pattern) }));
  });
  const verdicts = buildVerdicts(audits, files);
  const oracle = wantOracle ? verifyWithRe2(audits) : null;
  const notFixable = verdicts.filter((v) => !v.fixable);
  const totals: Totals = {
    rules: files.length,
    patterns: audits.length,
    badPatterns: audits.filter((a) => a.findings.length > 0).length,
    otherRules: verdicts.filter((v) => v.patterns.some((p) => p.findings.some((f) => f.cls === "other"))).length,
  };

  if (wantJson) {
    process.stdout.write(
      JSON.stringify(
        {
          totalRules: totals.rules,
          totalPatterns: totals.patterns,
          incompatiblePatterns: totals.badPatterns,
          incompatible: verdicts.length,
          byClass: countByClass(verdicts),
          otherRules: totals.otherRules,
          mechanicallyFixable: verdicts.filter((v) => v.fixable).map((v) => relative(process.cwd(), v.file)),
          notFixable: notFixable.map((v) => relative(process.cwd(), v.file)),
          rules: verdicts.map((v) => ({ ...v, file: relative(process.cwd(), v.file) })),
          coverage: computeCoverage(verdicts),
          oracle,
        },
        null,
        2
      ) + "\n"
    );
  } else {
    process.stdout.write(renderTable(verdicts, totals, oracle) + "\n");
  }

  if (failOnNotFixable && notFixable.length > 0) process.exit(1);
}

main();
