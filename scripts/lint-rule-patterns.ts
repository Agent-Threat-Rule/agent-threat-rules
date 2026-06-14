/**
 * Rule-quality lint — flags the loose-regex anti-patterns that produced the
 * confirmed false positives (00120 'nc'->async, 00149 'host'->prose,
 * 00220 greedy [^)]* span, 00422 benign verbs, 00547 bare localhost).
 *
 * Used two ways:
 *   1. Imported by check-rules-safety (Check 6) to route loose-pattern NEW
 *      rules to human review instead of auto-merge.
 *   2. Run standalone to audit the whole corpus:
 *        npx tsx scripts/lint-rule-patterns.ts
 *
 * Heuristic, not proof: a flag means "a human should confirm this regex is
 * scoped", not "this rule is broken". Read-only.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { load as yamlLoad } from "js-yaml";

// Short shell/command tokens that are also common English/word substrings.
// A bare match (no \b) of these is the 'nc'->async / 'host'->prose FP class.
const RISKY_BAREWORDS = new Set([
  "nc", "sh", "cp", "mv", "rm", "id", "ps", "ls", "dig", "host", "cat",
  "exec", "eval", "curl", "wget", "env", "set", "run", "dd", "su", "ln",
]);

export interface LintFlag {
  code: "unbounded-negated" | "unbounded-dotstar" | "wide-bridge" | "bareword" | "redos";
  detail: string;
}

/** Lint a single regex string. Returns the anti-patterns found. */
export function lintRegex(rx: string): LintFlag[] {
  const flags: LintFlag[] = [];
  // Catastrophic-backtracking: a SINGLE repeatable atom quantified inside a group
  // that is itself quantified ((a+)+, (\w*)*, (.*)*, ([a-z]+){2,}). This is the
  // shape that hangs the gate that runs the rule against the corpus. Non-overlapping
  // multi-atom bodies like (?:\s+[.\-]{1,}){15,} are linear and not flagged.
  if (/\((?:\?:)?(?:\\.|\[[^\]]*\]|[^()\[\]{}|+*?\\])[+*]\)(?:[+*]|\{\d+,?\d*\})/.test(rx)) {
    flags.push({ code: "redos", detail: "nested quantifier on a single atom — ReDoS / catastrophic-backtracking risk" });
  }
  if (/\[\^[^\]]+\]\*/.test(rx)) {
    flags.push({ code: "unbounded-negated", detail: "[^...]* greedy span can jump past intended context" });
  }
  if (/(?<!\\)\.\*/.test(rx) || /\[\\s\\S\]\*/.test(rx) || /\[\\S\\s\]\*/.test(rx)) {
    flags.push({ code: "unbounded-dotstar", detail: ".* / [\\s\\S]* matches across the whole input" });
  }
  const wide = [...rx.matchAll(/\{0,(\d+)\}/g)].map((m) => Number(m[1])).filter((n) => n >= 150);
  if (wide.length) {
    flags.push({ code: "wide-bridge", detail: `{0,${Math.max(...wide)}} bridges far-apart tokens` });
  }
  // bare short keyword followed by \s or \( without a preceding \b
  for (const m of rx.matchAll(/(?:\(|\?:|\||\^|\)|\s|\/|^)([a-z]{2,5})(?:\\s|\\\()/g)) {
    const kw = m[1];
    const start = m.index! + m[0].indexOf(kw);
    const before = rx.slice(Math.max(0, start - 2), start);
    if (before !== "\\b" && RISKY_BAREWORDS.has(kw)) {
      flags.push({ code: "bareword", detail: `keyword "${kw}" lacks a \\b word boundary (matches inside larger words)` });
    }
  }
  return flags;
}

/** Extract all regex condition values from a rule document. */
export function ruleRegexValues(doc: Record<string, unknown>): string[] {
  const out: string[] = [];
  const det = (doc.detection ?? {}) as Record<string, unknown>;
  const conds = (det.conditions ?? []) as Array<Record<string, unknown>>;
  for (const c of conds) {
    if (c && c.operator === "regex" && typeof c.value === "string") out.push(c.value);
  }
  return out;
}

/** Lint a whole rule document. Returns deduped flags across its regexes. */
export function lintRuleDoc(doc: Record<string, unknown>): LintFlag[] {
  const seen = new Set<string>();
  const flags: LintFlag[] = [];
  for (const rx of ruleRegexValues(doc)) {
    for (const f of lintRegex(rx)) {
      const k = `${f.code}:${f.detail}`;
      if (!seen.has(k)) { seen.add(k); flags.push(f); }
    }
  }
  return flags;
}

// ---- standalone CLI: audit the whole corpus ----
function walkRules(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walkRules(p, out);
    else if (e.endsWith(".yaml")) out.push(p);
  }
  return out;
}

function isMain(): boolean {
  return process.argv[1]?.endsWith("lint-rule-patterns.ts") ?? false;
}

if (isMain()) {
  const RULES_DIR = resolve(process.cwd(), "rules");
  const files = walkRules(RULES_DIR);
  let flagged = 0;
  const byStatus: Record<string, number> = {};
  for (const f of files) {
    let doc: Record<string, unknown>;
    try { doc = yamlLoad(readFileSync(f, "utf-8")) as Record<string, unknown>; } catch { continue; }
    if (!doc || typeof doc !== "object") continue;
    const flags = lintRuleDoc(doc);
    if (flags.length) {
      flagged++;
      const status = (doc.status as string) ?? "?";
      byStatus[status] = (byStatus[status] ?? 0) + 1;
    }
  }
  console.log(`Rules with loose-regex flags: ${flagged}/${files.length}`);
  console.log(`By status: ${JSON.stringify(byStatus)}`);
}
