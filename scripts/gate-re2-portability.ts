/**
 * RE2 portability ratchet -- CI gate over the whole ATR rule corpus.
 *
 * WHY A RATCHET INSTEAD OF A HARD GATE
 *   Downstream consumers compile ATR regexes with RE2-family engines (Go
 *   `regexp`, Rust `regex`, and every Sigma backend built on them). A large
 *   part of the corpus predates that requirement, and most of that debt needs
 *   a genuine refactor rather than a mechanical rewrite -- lookarounds and
 *   backreferences have no RE2 spelling. Failing every PR until the backlog is
 *   cleared would stop all rule work. So this gate does what the maturity-FP
 *   gate and the generalization gate do: it blocks NEW damage and lets the
 *   existing backlog drain on its own schedule.
 *
 * WHY FULL-SET AND NOT PR-DIFF SCOPED
 *   Rules land here by paths that never open a pull request -- the CVE
 *   collector and auto-crystallize commit straight to main. A gate that only
 *   inspects a PR diff cannot see those. Comparing the whole corpus against a
 *   baseline catches a new incompatibility no matter which door it came in
 *   through, and needs no git history (so a shallow checkout is enough).
 *
 * WHAT FAILS THE BUILD
 *   - A rule absent from the baseline has an RE2-incompatible regex. That is
 *     every newly authored rule, and every previously clean rule that a change
 *     made incompatible.
 *   - A baselined rule got worse: more incompatible patterns than the baseline
 *     records, or an incompatibility class it did not have before.
 *   - The static scanner disagrees with real RE2. Only checked when the audit
 *     ran with --verify-re2 and a Go toolchain was present; otherwise skipped,
 *     never guessed.
 *
 * WHAT DOES NOT FAIL THE BUILD
 *   - A baselined rule that improved or was fixed. It is reported so the
 *     baseline can be tightened with --write-baseline, matching the behaviour
 *     of scripts/eval-generalization.ts --gate.
 *
 * KNOWN GAP (deliberate)
 *   Baseline entries record a pattern count and a class set, not the pattern
 *   text. Editing an already-incompatible regex in place, without adding a new
 *   incompatibility, stays green. Recording pattern text would catch that, but
 *   would churn the baseline on every cosmetic regex edit. The inflow this
 *   gate exists to stop is newly generated rules, and the not-in-baseline
 *   check covers those completely.
 *
 * USAGE
 *   npx tsx scripts/gate-re2-portability.ts                      # audit + gate
 *   npx tsx scripts/gate-re2-portability.ts --audit report.json  # reuse a report
 *   npx tsx scripts/gate-re2-portability.ts --require-oracle     # CI: refuse to run without real RE2
 *   npx tsx scripts/gate-re2-portability.ts --write-baseline
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const BASELINE_PATH = resolve(process.cwd(), "data/re2-portability-baseline.json");
const AUDIT_SCRIPT = resolve(process.cwd(), "scripts/audit-re2-portability.ts");

const BASELINE_NOTE =
  "Rules whose detection regexes cannot be compiled by RE2 (Go regexp, Rust regex, " +
  "Sigma backends built on them). Ratchet only -- new entries must be fixed, not added. " +
  "See scripts/gate-re2-portability.ts.";

/** Findings the audit reports outside the five named classes need a human. */
const NEEDS_HUMAN_CLASS = "other";

// ---------------------------------------------------------------------------
// Shapes emitted by scripts/audit-re2-portability.ts --json
// ---------------------------------------------------------------------------

interface AuditFinding {
  readonly cls: string;
  readonly token: string;
  /** Character offset of the construct inside the pattern string. */
  readonly index: number;
  readonly detail: string;
}

interface AuditPattern {
  readonly location: string;
  readonly pattern: string;
  readonly findings: readonly AuditFinding[];
}

interface AuditRule {
  readonly file: string;
  readonly ruleId: string;
  readonly patterns: readonly AuditPattern[];
}

interface AuditOracle {
  readonly available: boolean;
  readonly disagreements: readonly string[];
}

interface AuditReport {
  readonly totalRules: number;
  readonly totalPatterns: number;
  readonly incompatiblePatterns: number;
  readonly rules: readonly AuditRule[];
  readonly oracle: AuditOracle | null;
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

interface BaselineEntry {
  /** How many distinct regex patterns in this rule RE2 cannot compile. */
  readonly patterns: number;
  /** Incompatibility classes present, sorted. "other" means a human must look. */
  readonly classes: readonly string[];
}

interface Baseline {
  readonly generatedAt: string;
  readonly note: string;
  readonly corpus: { readonly rules: number; readonly regexPatterns: number };
  readonly knownNotPortable: Readonly<Record<string, BaselineEntry>>;
}

const EMPTY_BASELINE: Baseline = {
  generatedAt: "",
  note: BASELINE_NOTE,
  corpus: { rules: 0, regexPatterns: 0 },
  knownNotPortable: {},
};

/** Parse and validate a baseline file. Never trusts the shape on disk. */
function loadBaseline(): Baseline {
  if (!existsSync(BASELINE_PATH)) return EMPTY_BASELINE;
  const doc = readJson(BASELINE_PATH) as Partial<Baseline>;
  const known = doc.knownNotPortable;
  // An array here would pass a bare typeof check and then read as an EMPTY
  // baseline, turning a corrupt file into "every rule is a new regression".
  if (known === null || typeof known !== "object" || Array.isArray(known)) {
    throw new Error(`${BASELINE_PATH}: "knownNotPortable" must be an object of ruleId -> entry`);
  }
  for (const [id, entry] of Object.entries(known)) {
    const ok = entry && typeof entry.patterns === "number" && Array.isArray(entry.classes);
    if (!ok) throw new Error(`${BASELINE_PATH}: entry "${id}" needs {patterns:number, classes:string[]}`);
  }
  return { ...EMPTY_BASELINE, ...doc, knownNotPortable: known as Record<string, BaselineEntry> };
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`${path}: not readable as JSON -- ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Audit acquisition
// ---------------------------------------------------------------------------

function parseAudit(raw: string, source: string): AuditReport {
  let doc: Partial<AuditReport>;
  try {
    doc = JSON.parse(raw) as Partial<AuditReport>;
  } catch (err) {
    throw new Error(`${source}: not valid JSON -- ${(err as Error).message}`);
  }
  if (typeof doc.totalRules !== "number" || !Array.isArray(doc.rules)) {
    throw new Error(`${source}: not an audit report (expected totalRules + rules[]). Produce it with: npx tsx scripts/audit-re2-portability.ts --json`);
  }
  return doc as AuditReport;
}

/**
 * Run the audit in-process-adjacent. Uses the same node binary with tsx
 * preloaded so no npx lookup or global install is involved. --verify-re2 is
 * best effort: with a Go toolchain the verdict is measured against real RE2,
 * without one the audit silently reports the oracle as unavailable.
 */
function spawnAudit(): AuditReport {
  const stdout = execFileSync(
    process.execPath,
    ["--import", "tsx", AUDIT_SCRIPT, "--json", "--verify-re2"],
    { encoding: "utf8", maxBuffer: 128 * 1024 * 1024 }
  );
  return parseAudit(stdout, "audit subprocess");
}

function acquireAudit(auditPath: string): AuditReport {
  if (!auditPath) return spawnAudit();
  if (!existsSync(auditPath)) throw new Error(`--audit ${auditPath}: file not found`);
  return parseAudit(readFileSync(auditPath, "utf8"), auditPath);
}

// ---------------------------------------------------------------------------
// Current state
// ---------------------------------------------------------------------------

interface Observed extends BaselineEntry {
  readonly ruleId: string;
  readonly file: string;
  readonly detail: readonly AuditPattern[];
}

/**
 * Collapse the audit report into one entry per incompatible rule. Classes are
 * read off the findings rather than the audit's own `classes` field so that
 * "other" findings are represented instead of vanishing.
 */
function observe(report: AuditReport): ReadonlyMap<string, Observed> {
  const withFindings = report.rules.filter((r) => r.patterns.some((p) => p.findings.length > 0));
  return new Map(
    withFindings.map((rule) => {
      const bad = rule.patterns.filter((p) => p.findings.length > 0);
      const classes = [...new Set(bad.flatMap((p) => p.findings.map((f) => f.cls)))].sort();
      return [rule.ruleId, { ruleId: rule.ruleId, file: rule.file, patterns: bad.length, classes, detail: bad }];
    })
  );
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

interface Regression {
  readonly rule: Observed;
  readonly reason: string;
  /**
   * Classes this rule did not have in the baseline. When non-empty the report
   * shows only these findings, so a rule with pre-existing debt does not bury
   * the actual regression under dozens of already-accepted lines.
   */
  readonly gained: readonly string[];
}

interface Comparison {
  readonly added: readonly Observed[];
  readonly worsened: readonly Regression[];
  readonly improved: readonly string[];
  readonly resolved: readonly string[];
}

function worseThan(current: Observed, base: BaselineEntry): Omit<Regression, "rule"> | null {
  const gained = current.classes.filter((c) => !base.classes.includes(c));
  if (gained.length > 0) return { reason: `new incompatibility class: ${gained.join(", ")}`, gained };
  if (current.patterns > base.patterns) {
    return { reason: `incompatible patterns rose ${base.patterns} -> ${current.patterns}`, gained: [] };
  }
  return null;
}

function betterThan(current: Observed | undefined, base: BaselineEntry): boolean {
  if (!current) return false;
  const dropped = base.classes.filter((c) => !current.classes.includes(c));
  return current.patterns < base.patterns || dropped.length > 0;
}

function compare(current: ReadonlyMap<string, Observed>, base: Baseline): Comparison {
  const known = base.knownNotPortable;
  const added = [...current.values()].filter((o) => !(o.ruleId in known));
  const worsened = [...current.values()].flatMap((o) => {
    const entry = known[o.ruleId];
    if (!entry) return [];
    const verdict = worseThan(o, entry);
    return verdict ? [{ rule: o, ...verdict }] : [];
  });
  const baselineIds = Object.keys(known).sort();
  return {
    added,
    worsened,
    improved: baselineIds.filter((id) => betterThan(current.get(id), known[id]!)),
    resolved: baselineIds.filter((id) => !current.has(id)),
  };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/** Keep one rule's block short enough that a CI log stays readable. */
const MAX_DETAIL_LINES = 12;

/**
 * One indented block per offending rule: where it is and what RE2 chokes on.
 * `focus`, when non-empty, limits the findings to the classes that actually
 * regressed, so pre-existing accepted debt in the same rule stays out of the way.
 */
function renderRule(rule: Observed, reason: string, focus: readonly string[] = []): string[] {
  const keep = (f: AuditFinding): boolean => focus.length === 0 || focus.includes(f.cls);
  const body = rule.detail.flatMap((p) =>
    p.findings.filter(keep).map((f) => `      ${p.location} @${f.index}  [${f.cls}] ${f.token}  ${f.detail}`)
  );
  const shown = body.slice(0, MAX_DETAIL_LINES);
  const rest = body.length - shown.length;
  return [
    `  - ${rule.ruleId}  ${reason}`,
    `      ${rule.file}`,
    ...shown,
    ...(rest > 0 ? [`      ... and ${rest} more (run: npx tsx scripts/audit-re2-portability.ts)`] : []),
  ];
}

function fixHint(rules: readonly Observed[]): string[] {
  const classes = new Set(rules.flatMap((r) => r.classes));
  const lines: string[] = [];
  if (classes.has("unicodeEscape")) {
    lines.push("  unicodeEscape  rewrite \\uXXXX as \\x{XXXX} -- but the rewrite is NOT always");
    lines.push("                 equivalent, so confirm with scripts/verify-re2-equivalence.ts.");
    lines.push("                 It compiles under RE2 and silently changes meaning when the");
    lines.push("                 pattern names a UTF-16 surrogate (\\uD800-\\uDFFF is half of a pair");
    lines.push("                 standing for one astral code point -- write [\\x{E0000}-\\x{E007F}],");
    lines.push("                 not two halves), or leans on \\s/\\S (JS includes Unicode spaces,");
    lines.push("                 RE2 restricts them to ASCII), or counts with . and bounded repeats");
    lines.push("                 (JS counts UTF-16 code units, RE2 counts runes).");
  }
  if (classes.has("namedGroup")) lines.push("  namedGroup     rewrite (?<name>...) as (?P<name>...)");
  if (classes.has("lookaround")) lines.push("  lookaround     RE2 has no lookahead/lookbehind. Restructure the pattern, or split the condition.");
  if (classes.has("backreference")) lines.push("  backreference  RE2 cannot backtrack. Spell the repetition out.");
  if (classes.has("atomicOrPossessive")) lines.push("  atomic/possessive  drop it; RE2 is linear-time and needs no catastrophic-backtracking guard.");
  if (classes.has(NEEDS_HUMAN_CLASS)) lines.push("  other          repeat bound over 1000, or \\b inside a character class. Both need a human decision.");
  return lines.length ? ["", "How to fix:", ...lines] : [];
}

function renderOracle(oracle: AuditOracle | null): string[] {
  if (!oracle || !oracle.available) {
    return ["oracle: not run (no Go toolchain, or audit ran without --verify-re2); verdict is static analysis"];
  }
  const n = oracle.disagreements.length;
  return n === 0
    ? ["oracle: real RE2 (Go regexp) agrees with the scanner on every pattern"]
    : [`oracle: real RE2 disagrees with the scanner on ${n} pattern(s)`, ...oracle.disagreements.slice(0, 20).map((d) => `  ${d}`)];
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/**
 * CI runs with --require-oracle so the verdict is always measured against real
 * RE2 rather than inferred. This matters more than it looks: the hand-written
 * scanner had two genuine blind spots that only surfaced when every pattern was
 * fed to Go's regexp. Silently degrading to static analysis because a runner
 * image dropped its Go toolchain would leave a gate that still reports PASS
 * while no longer checking what it claims to check.
 */
function requireOracle(oracle: AuditOracle | null): void {
  if (oracle?.available) return;
  throw new Error(
    "--require-oracle was set but the RE2 oracle did not run. Install a Go toolchain " +
      "and pass --verify-re2 to scripts/audit-re2-portability.ts. Refusing to report a " +
      "verdict from static analysis alone."
  );
}

function runGate(report: AuditReport, current: ReadonlyMap<string, Observed>, base: Baseline): never {
  const { added, worsened, improved, resolved } = compare(current, base);
  const oracle = report.oracle;
  const oracleBroken = Boolean(oracle?.available) && (oracle?.disagreements.length ?? 0) > 0;
  const out: string[] = [
    "",
    "=== ATR RE2 Portability GATE ===",
    `corpus: ${report.totalRules} rules, ${report.totalPatterns} regex patterns`,
    `not portable: ${current.size} rules / ${report.incompatiblePatterns} patterns (baseline ${Object.keys(base.knownNotPortable).length} rules)`,
    ...renderOracle(oracle),
  ];

  if (improved.length || resolved.length) {
    out.push("", "RATCHET -- these improved and should be tightened in the baseline:");
    out.push(...resolved.map((id) => `  + ${id}: now fully RE2 portable`));
    out.push(...improved.map((id) => `  + ${id}: fewer incompatibilities than the baseline records`));
    out.push("  (run --write-baseline to tighten)");
  }

  if (added.length === 0 && worsened.length === 0 && !oracleBroken) {
    out.push("", "GATE PASS -- no new RE2 incompatibility.", "");
    process.stdout.write(out.join("\n"));
    process.exit(0);
  }

  // The oracle can fail on its own, with every rule still inside the baseline.
  // Announcing "new incompatibility introduced" and then listing nothing sends
  // an author hunting for a rule change that does not exist.
  const regressed = added.length > 0 || worsened.length > 0;
  if (regressed) {
    out.push("", "GATE FAIL -- new RE2 incompatibility introduced:");
    out.push(...added.flatMap((r) => renderRule(r, "(not in baseline)")));
    out.push(...worsened.flatMap((w) => renderRule(w.rule, `(${w.reason})`, w.gained)));
    out.push(...fixHint([...added, ...worsened.map((w) => w.rule)]));
    out.push("", "Downstream consumers compile these with RE2 and will drop the rule outright.", "Do NOT widen the baseline to silence this.");
  }
  if (oracleBroken) {
    out.push(
      "",
      "GATE FAIL -- the static scanner no longer matches real RE2.",
      "  Every pattern above was classified by scripts/audit-re2-portability.ts, and real",
      "  RE2 came to a different verdict on the patterns listed under `oracle:`. Fix the",
      "  scanner before trusting this gate; the baseline is meaningless while they disagree."
    );
  }
  out.push("");
  process.stdout.write(out.join("\n"));
  process.exit(1);
}

function writeBaseline(report: AuditReport, current: ReadonlyMap<string, Observed>): void {
  const ids = [...current.keys()].sort();
  const baseline: Baseline = {
    generatedAt: new Date().toISOString(),
    note: BASELINE_NOTE,
    corpus: { rules: report.totalRules, regexPatterns: report.totalPatterns },
    knownNotPortable: Object.fromEntries(
      ids.map((id) => {
        const o = current.get(id)!;
        return [id, { patterns: o.patterns, classes: o.classes }];
      })
    ),
  };
  writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + "\n");
  process.stdout.write(`wrote baseline: ${ids.length} not-portable rules -> ${BASELINE_PATH}\n`);
}

function main(): void {
  const argv = process.argv.slice(2);
  const auditIdx = argv.indexOf("--audit");
  const auditPath = auditIdx === -1 ? "" : (argv[auditIdx + 1] ?? "");
  if (auditIdx !== -1 && !auditPath) throw new Error("--audit needs a path to an audit --json report");

  const report = acquireAudit(auditPath);
  const current = observe(report);

  if (argv.includes("--write-baseline")) {
    writeBaseline(report, current);
    return;
  }
  if (argv.includes("--require-oracle")) requireOracle(report.oracle);
  runGate(report, current, loadBaseline());
}

/**
 * Exit codes are distinct on purpose: 1 means rules regressed and an author
 * must act, 2 means the gate itself could not run. A CI log that conflates the
 * two teaches people to ignore the gate.
 */
try {
  main();
} catch (err) {
  process.stderr.write(`\nRE2 portability gate could not run: ${(err as Error).message}\n\n`);
  process.exit(2);
}
