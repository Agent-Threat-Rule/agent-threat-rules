/**
 * Mechanical RE2-dialect rewrite for ATR rule patterns.
 *
 * Two constructs have an exactly equivalent RE2 spelling and can therefore be
 * rewritten by a script rather than by a human:
 *
 *   JS `\uXXXX` / `\u{XXXXX}`  ->  RE2 `\x{XXXX}` / `\x{XXXXX}`
 *   JS `(?<name>...)`          ->  RE2 `(?P<name>...)`
 *
 * Everything else that RE2 rejects (lookaround, backreference, atomic group,
 * possessive quantifier, out-of-range repeat bounds) changes the matched
 * language when removed, so this script never touches it.
 *
 * WHY A WALK AND NOT A REPLACE
 *   `s.replace(/\\u([0-9a-fA-F]{4})/g, ...)` is wrong. In the pattern
 *   `\\u0041` (an escaped backslash followed by a literal `u0041`, i.e. the
 *   rule is looking for the seven characters `A` in the payload) that
 *   regex matches starting at the SECOND backslash and produces `\\x{0041}`,
 *   silently turning a search for the text `A` into a search for
 *   `\` followed by `A`. ATR has rules that hunt exactly that text -- see
 *   ATR-2026-00258 condition #3. So the rewriter walks the pattern tracking
 *   backslash and character-class state, and only rewrites escapes that are
 *   genuinely escape-initial.
 *
 * WHERE THE REWRITE IS SAFE TO APPLY
 *   NOT in the rule YAML. ATR's own engine compiles these strings with
 *   `new RegExp(source, flags)` and picks its flags with
 *   `pattern.includes('\\u{') || pattern.includes('\\p{') ? 'iu' : 'i'`
 *   (src/engine.ts). JavaScript has no `\x{...}` escape: without `u` it
 *   degrades via Annex B to a literal `x` plus a brace quantifier, and with
 *   `u` it is a SyntaxError. Rewriting the YAML therefore breaks detection in
 *   the primary engine. `--apply` consequently refuses to write inside
 *   `rules/` unless `--force-rules` is passed, and prints why.
 *   The supported consumer of this module is the export path
 *   (scripts/generate-sigma.py, scripts/compile-yara.ts), which emits for RE2
 *   engines and where the rewrite is both safe and necessary.
 *
 * USAGE
 *   npx tsx scripts/fix-re2-escapes.ts                  # dry run (default)
 *   npx tsx scripts/fix-re2-escapes.ts --json
 *   npx tsx scripts/fix-re2-escapes.ts --apply          # refuses on rules/
 *   npx tsx scripts/fix-re2-escapes.ts --apply --force-rules
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { load as yamlLoad, dump as yamlDump } from "js-yaml";

const RULES_DIR = resolve(process.cwd(), "rules");

export type RewriteKind = "unicodeEscape" | "namedGroup";

export interface Rewrite {
  readonly kind: RewriteKind;
  readonly index: number;
  readonly token: string;
  readonly replacement: string;
}

const HEX4 = /^[0-9a-fA-F]{4}$/;
const BRACED_HEX = /^[0-9a-fA-F]{1,6}$/;
const GROUP_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

// ---------------------------------------------------------------------------
// Escape-aware planner
// ---------------------------------------------------------------------------

/** A `\u...` escape starting at `i`, or null when it is not a rewritable one. */
function planUnicodeEscape(rx: string, i: number): Rewrite | null {
  if (rx[i + 2] === "{") {
    const end = rx.indexOf("}", i + 3);
    if (end === -1) return null;
    const hex = rx.slice(i + 3, end);
    if (!BRACED_HEX.test(hex)) return null;
    return { kind: "unicodeEscape", index: i, token: rx.slice(i, end + 1), replacement: `\\x{${hex}}` };
  }
  const hex = rx.slice(i + 2, i + 6);
  if (!HEX4.test(hex)) return null;
  return { kind: "unicodeEscape", index: i, token: `\\u${hex}`, replacement: `\\x{${hex}}` };
}

/** A JS named group `(?<name>` at `i`, or null (lookbehind is not one). */
function planNamedGroup(rx: string, i: number): Rewrite | null {
  if (rx.startsWith("(?<=", i) || rx.startsWith("(?<!", i)) return null;
  if (!rx.startsWith("(?<", i)) return null;
  const end = rx.indexOf(">", i + 3);
  if (end === -1) return null;
  const name = rx.slice(i + 3, end);
  if (!GROUP_NAME.test(name)) return null;
  return { kind: "namedGroup", index: i, token: rx.slice(i, end + 1), replacement: `(?P<${name}>` };
}

/** Index just past the construct at `i`, used to keep the walk in step. */
function skipWidth(rx: string, i: number, inClass: boolean): number {
  if (rx[i] === "\\") return i + 2;
  if (inClass) return i + 1;
  return i + 1;
}

/**
 * Walk `rx` and return every mechanically rewritable construct, in source
 * order. Pure: allocates a new array and never touches the input.
 *
 * The walk exists to distinguish an escape-initial backslash from an escaped
 * one, and to keep `(?<` inside a character class (where it is four literals)
 * from being read as a group opener.
 */
export function planRewrites(rx: string): readonly Rewrite[] {
  const out: Rewrite[] = [];
  let i = 0;
  let inClass = false;
  while (i < rx.length) {
    const ch = rx[i]!;
    if (ch === "\\") {
      const planned = rx[i + 1] === "u" ? planUnicodeEscape(rx, i) : null;
      if (planned) {
        out.push(planned);
        i += planned.token.length;
        continue;
      }
      i = skipWidth(rx, i, inClass);
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
      const planned = planNamedGroup(rx, i);
      if (planned) {
        out.push(planned);
        i += planned.token.length;
        continue;
      }
    }
    i += 1;
  }
  return out;
}

/** Apply a plan right-to-left so earlier indices stay valid. Never mutates. */
export function applyRewrites(rx: string, plan: readonly Rewrite[]): string {
  return [...plan]
    .sort((a, b) => b.index - a.index)
    .reduce((acc, r) => acc.slice(0, r.index) + r.replacement + acc.slice(r.index + r.token.length), rx);
}

/** Convenience: plan + apply in one call. */
export function rewriteForRe2(rx: string): { readonly source: string; readonly plan: readonly Rewrite[] } {
  const plan = planRewrites(rx);
  return { source: plan.length === 0 ? rx : applyRewrites(rx, plan), plan };
}

// ---------------------------------------------------------------------------
// Rule corpus access
// ---------------------------------------------------------------------------

export interface PatternRef {
  readonly file: string;
  readonly ruleId: string;
  readonly index: number;
  readonly field: string;
  readonly pattern: string;
}

export function collectRuleFiles(dir: string = RULES_DIR): string[] {
  return readdirSync(dir)
    .sort()
    .flatMap((entry) => {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) return collectRuleFiles(full);
      return /\.ya?ml$/i.test(entry) ? [full] : [];
    });
}

function isRegexOperator(raw: unknown): boolean {
  const op = String(raw ?? "regex").trim().toLowerCase();
  return op === "regex" || op === "regex_all" || op === "regex_any" || op === "not_regex";
}

/** Regex strings the ATR engine compiles from one rule document. */
export function extractPatterns(doc: unknown, file: string): PatternRef[] {
  const rule = (doc ?? {}) as Record<string, unknown>;
  const ruleId = String(rule["id"] ?? "(no id)");
  const detection = (rule["detection"] ?? {}) as Record<string, unknown>;
  const conditions = detection["conditions"];
  if (!Array.isArray(conditions)) return [];
  return conditions.flatMap((cond, index) => {
    const c = (cond ?? {}) as Record<string, unknown>;
    if (!isRegexOperator(c["operator"])) return [];
    const pattern = c["value"];
    if (typeof pattern !== "string") return [];
    return [{ file, ruleId, index, field: String(c["field"] ?? "content"), pattern }];
  });
}

export function loadCorpus(dir: string = RULES_DIR): PatternRef[] {
  return collectRuleFiles(dir).flatMap((file) => extractPatterns(yamlLoad(readFileSync(file, "utf8")), file));
}

// ---------------------------------------------------------------------------
// YAML surgical edit
// ---------------------------------------------------------------------------

const VALUE_LINE = /^(\s*(?:-\s+)?value:[ \t]+)(\S.*)$/;

/** Parse one YAML scalar fragment back to its string, or null if it is not one. */
function parseScalar(raw: string): string | null {
  try {
    const parsed = yamlLoad(raw);
    return typeof parsed === "string" ? parsed : null;
  } catch {
    return null;
  }
}

function renderScalar(value: string): string {
  return yamlDump(value, { quotingType: '"', forceQuotes: true, lineWidth: -1 }).replace(/\n$/, "");
}

export interface FileEdit {
  readonly file: string;
  readonly linesChanged: number;
  readonly patternsChanged: number;
  readonly text: string;
  readonly unmatched: readonly string[];
}

/**
 * Rewrite every `value:` scalar in `text` whose parsed content appears in
 * `targets`. Returns new text; the original string is never mutated.
 */
export function rewriteYamlText(text: string, targets: ReadonlySet<string>): Omit<FileEdit, "file"> {
  const seen = new Set<string>();
  let linesChanged = 0;
  const out = text.split("\n").map((line) => {
    const m = VALUE_LINE.exec(line);
    if (!m) return line;
    const parsed = parseScalar(m[2]!);
    if (parsed === null || !targets.has(parsed)) return line;
    const { source, plan } = rewriteForRe2(parsed);
    if (plan.length === 0) return line;
    seen.add(parsed);
    linesChanged += 1;
    return `${m[1]}${renderScalar(source)}`;
  });
  return {
    linesChanged,
    patternsChanged: seen.size,
    text: out.join("\n"),
    unmatched: [...targets].filter((t) => !seen.has(t)),
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface PlannedPattern extends PatternRef {
  readonly rewritten: string;
  readonly plan: readonly Rewrite[];
}

function planCorpus(refs: readonly PatternRef[]): PlannedPattern[] {
  return refs.flatMap((ref) => {
    const { source, plan } = rewriteForRe2(ref.pattern);
    return plan.length === 0 ? [] : [{ ...ref, rewritten: source, plan }];
  });
}

function renderPlan(planned: readonly PlannedPattern[], applied: boolean): string {
  const files = [...new Set(planned.map((p) => p.file))];
  const byKind = planned.flatMap((p) => p.plan).reduce<Record<string, number>>((acc, r) => ({ ...acc, [r.kind]: (acc[r.kind] ?? 0) + 1 }), {});
  return [
    `RE2 mechanical escape rewrite -- ${applied ? "APPLIED" : "DRY RUN (default; pass --apply to write)"}`,
    "=".repeat(72),
    `rule files touched   ${files.length}`,
    `patterns rewritten   ${planned.length}`,
    `tokens rewritten     ${Object.entries(byKind).map(([k, n]) => `${k}=${n}`).join(" ") || "0"}`,
    "",
    ...planned.flatMap((p) => [
      `  ${p.ruleId} detection.conditions[${p.index}].value (${p.field})`,
      `    -  ${p.pattern}`,
      `    +  ${p.rewritten}`,
    ]),
  ].join("\n");
}

function writeEdits(planned: readonly PlannedPattern[]): number {
  const byFile = planned.reduce<Map<string, Set<string>>>((acc, p) => {
    const next = acc.get(p.file) ?? new Set<string>();
    next.add(p.pattern);
    return new Map(acc).set(p.file, next);
  }, new Map());
  let written = 0;
  for (const [file, targets] of byFile) {
    const before = readFileSync(file, "utf8");
    const edit = rewriteYamlText(before, targets);
    if (edit.unmatched.length > 0) {
      console.error(`[fix-re2] ${relative(process.cwd(), file)}: ${edit.unmatched.length} pattern(s) not found on a value: line; skipped`);
    }
    if (edit.text === before) continue;
    writeFileSync(file, edit.text, "utf8");
    written += 1;
  }
  return written;
}

const RULES_GUARD = [
  "REFUSING to rewrite rules/ .",
  "ATR's engine compiles these patterns with JavaScript's RegExp, which has no",
  "\\x{...} escape: without the u flag it degrades to a literal x plus a brace",
  "quantifier, and with the u flag it is a SyntaxError. Rewriting the rule YAML",
  "silently destroys detection in the primary engine. Apply this rewrite in the",
  "RE2-targeting exporters instead. Pass --force-rules to override.",
].join("\n");

function main(): void {
  const argv = process.argv.slice(2);
  const apply = argv.includes("--apply");
  const force = argv.includes("--force-rules");
  const planned = planCorpus(loadCorpus());

  if (argv.includes("--json")) {
    process.stdout.write(
      JSON.stringify(
        {
          applied: apply && force,
          files: [...new Set(planned.map((p) => relative(process.cwd(), p.file)))],
          patterns: planned.map((p) => ({
            ruleId: p.ruleId,
            file: relative(process.cwd(), p.file),
            location: `detection.conditions[${p.index}].value`,
            before: p.pattern,
            after: p.rewritten,
            tokens: p.plan.map((r) => ({ kind: r.kind, token: r.token, replacement: r.replacement })),
          })),
        },
        null,
        2
      ) + "\n"
    );
  } else {
    process.stdout.write(renderPlan(planned, apply && force) + "\n");
  }

  if (!apply) return;
  if (!force) {
    console.error(`\n${RULES_GUARD}`);
    process.exit(2);
  }
  const written = writeEdits(planned);
  console.error(`\n[fix-re2] wrote ${written} file(s).`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();
