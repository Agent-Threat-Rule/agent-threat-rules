/**
 * Differential equivalence proof for the mechanical RE2 escape rewrite.
 *
 * scripts/fix-re2-escapes.ts claims that `\uXXXX -> \x{XXXX}` and
 * `(?<n> -> (?P<n>` preserve meaning. A claim about regex semantics is only
 * worth what an execution proves, so this script does not reason about it: it
 * runs both spellings over a large shared input battery in every engine that
 * matters and compares the match vectors position by position.
 *
 * THREE ARMS
 *   JS(original)    ATR's own engine path: normalizeRegex() then
 *                   new RegExp(src, src.includes('\\u{')||'\\p{' ? 'iu':'i').
 *                   This is the reference behaviour -- what ATR detects today.
 *   JS(rewritten)   Same compile path applied to the rewritten spelling.
 *                   Equal vectors here mean the rewrite is safe to write into
 *                   the rule YAML. Unequal means writing it breaks detection.
 *   RE2(rewritten)  Go's regexp package (which IS RE2), the engine every
 *                   downstream Sigma/YARA-adjacent consumer compiles to.
 *                   Equal vectors mean the rewrite is a faithful port.
 *
 * A fourth control arm compiles the ORIGINAL under RE2 to confirm that the
 * pattern really is the broken one and the audit is not inventing a problem.
 *
 * INPUT BATTERY (per pattern)
 *   1. every test_cases / evasion_tests input in the whole rule corpus
 *   2. a sample of the benign skill corpus (real-world negative text)
 *   3. codepoint boundary probes built from the pattern's own escapes:
 *      each referenced codepoint and its two neighbours, range endpoints and
 *      midpoints, each alone / repeated / embedded in carrier text
 *   4. seeded pseudo-random fuzz over an alphabet made of those codepoints
 *      plus the pattern's own ASCII literals
 *
 * A single position where two arms disagree disqualifies the rewrite for that
 * pattern; the script reports it rather than averaging it away.
 *
 * USAGE
 *   npx tsx scripts/verify-re2-equivalence.ts
 *   npx tsx scripts/verify-re2-equivalence.ts --json
 *   npx tsx scripts/verify-re2-equivalence.ts --samples 4000
 */
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, relative } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { load as yamlLoad } from "js-yaml";
import { loadCorpus, collectRuleFiles, rewriteForRe2, type PatternRef } from "./fix-re2-escapes.js";
import { needsUnicodeFlag } from "../src/engine.js";

const BENIGN_DIR = resolve(process.cwd(), "data/skill-benchmark/benign");
const BENIGN_SAMPLE = 30;
const BENIGN_CHARS = 1500;
const DEFAULT_FUZZ = 6000;
const MAX_FUZZ_LEN = 40;

// ---------------------------------------------------------------------------
// ATR engine compile path (mirrors src/engine.ts compilePatterns)
// ---------------------------------------------------------------------------

function normalizeRegex(pattern: string): string {
  return pattern.replace(/^\(\?[imsx]+\)/, "");
}

export function engineCompile(value: string): RegExp | null {
  const normalized = normalizeRegex(value);
  const flags = needsUnicodeFlag(normalized) ? "iu" : "i";
  try {
    return new RegExp(normalized, flags);
  } catch {
    return null;
  }
}

function jsVector(value: string, inputs: readonly string[]): string | null {
  const re = engineCompile(value);
  if (re === null) return null;
  return inputs.map((s) => (re.test(s) ? "1" : "0")).join("");
}

// ---------------------------------------------------------------------------
// Input battery
// ---------------------------------------------------------------------------

/** Every `input:` string under test_cases / evasion_tests in one rule doc. */
function testCaseInputs(doc: unknown): string[] {
  const rule = (doc ?? {}) as Record<string, unknown>;
  const tc = (rule["test_cases"] ?? {}) as Record<string, unknown>;
  const groups = [tc["true_positives"], tc["true_negatives"], rule["evasion_tests"]];
  return groups.flatMap((g) =>
    (Array.isArray(g) ? g : []).flatMap((entry) => {
      const value = ((entry ?? {}) as Record<string, unknown>)["input"];
      return typeof value === "string" ? [value] : [];
    })
  );
}

function loadCorpusTestInputs(): string[] {
  return collectRuleFiles().flatMap((f) => testCaseInputs(yamlLoad(readFileSync(f, "utf8"))));
}

function loadBenignSample(): string[] {
  if (!existsSync(BENIGN_DIR)) return [];
  return readdirSync(BENIGN_DIR, { withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => e.name)
    .sort()
    .slice(0, BENIGN_SAMPLE)
    .map((f) => readFileSync(join(BENIGN_DIR, f), "utf8").slice(0, BENIGN_CHARS));
}

/** Codepoints named by the pattern's own \u escapes, plus range interiors. */
function referencedCodepoints(pattern: string): number[] {
  const plan = rewriteForRe2(pattern).plan.filter((r) => r.kind === "unicodeEscape");
  const cps = plan.map((r) => parseInt(r.replacement.slice(3, -1), 16));
  const ranges = plan.flatMap((r, i) => {
    const next = plan[i + 1];
    if (!next || pattern[r.index + r.token.length] !== "-") return [];
    if (next.index !== r.index + r.token.length + 1) return [];
    const lo = parseInt(r.replacement.slice(3, -1), 16);
    const hi = parseInt(next.replacement.slice(3, -1), 16);
    return [Math.floor((lo + hi) / 2), lo + 1, hi - 1];
  });
  const neighbours = cps.flatMap((cp) => [cp - 1, cp, cp + 1]);
  return [...new Set([...neighbours, ...ranges])].filter((cp) => cp >= 0 && cp <= 0x10ffff).sort((a, b) => a - b);
}

/** ASCII literal words in the pattern -- the carrier text a real payload has. */
function carrierWords(pattern: string): string[] {
  return [...new Set(pattern.match(/[A-Za-z]{4,}/g) ?? [])]
    .filter((w) => !/^(?:u|x|s|d|w|b|n|r|t)$/.test(w))
    .slice(0, 8);
}

function boundaryProbes(pattern: string): string[] {
  const cps = referencedCodepoints(pattern);
  const words = carrierWords(pattern);
  const chars = cps.map((cp) => String.fromCodePoint(cp));
  return chars.flatMap((ch) => [
    ch,
    ch.repeat(3),
    ch.repeat(8),
    ch.repeat(16),
    `abc${ch}def`,
    `abc${ch.repeat(5)}def`,
    `${ch} ${ch} ${ch}`,
    `Encoded: ${ch.repeat(10)}`,
    ...words.slice(0, 3).flatMap((w) => [`${w} ${ch.repeat(4)}`, `${ch.repeat(4)} ${w}`, `${w}${ch}`]),
  ]);
}

/**
 * Probes aimed at what the REWRITE means to a reader that does not know
 * `\x{...}`. JavaScript without the `u` flag resolves `\x{0041}` via Annex B
 * to a literal `x` followed by the brace quantifier `{0041}` -- i.e. "the
 * letter x, 41 times". Unless the battery contains such strings, a rewritten
 * pattern can look equivalent purely because nothing ever exercised the
 * degraded reading. These probes make that reading observable.
 */
function rewriteArtifactProbes(after: string): string[] {
  const braces = [...new Set(after.match(/x\{[0-9a-fA-F]+\}/g) ?? [])];
  const counts = [...new Set(braces.map((b) => Number(b.slice(2, -1).replace(/[a-fA-F]/g, ""))))]
    .filter((n) => Number.isFinite(n) && n > 0 && n <= 400);
  return [
    ...braces,
    ...braces.map((b) => `abc${b}def`),
    ...braces.map((b) => `${b}${b}${b}`),
    ...counts.map((n) => "x".repeat(n)),
    ...counts.map((n) => `abc${"x".repeat(n)}def`),
    ...[1, 2, 3, 4, 5, 8, 16, 32, 41, 64, 96, 127, 255].map((n) => "x".repeat(n)),
    "x{",
    "}",
    "x{0041}",
    "\\x{200B}",
  ];
}

/**
 * Structured probes. Random fuzz cannot build "ixgnore" out of
 * "i<ZWSP>gnore": that needs seven specific characters in order. But the
 * degraded JS reading of `[\x{200B}...]` admits exactly the literals `x`, `{`,
 * `}` and hex digits, so the divergence is reachable only by CONSTRUCTING it.
 * Given an input that one arm already matches, swap the codepoints the pattern
 * names for the characters the rewrite accidentally admits, and vice versa.
 */
function mutationProbes(pattern: string, after: string, matched: readonly string[]): string[] {
  const cps = referencedCodepoints(pattern).map((cp) => String.fromCodePoint(cp));
  const vocab = [...new Set(after.match(/[\x20-\x7e]/g) ?? [])].slice(0, 12);
  const present = cps.filter((c) => matched.some((s) => s.includes(c)));
  const swapOut = matched
    .slice(0, 12)
    .flatMap((s) => [
      ...vocab.map((v) => present.reduce((acc, c) => acc.split(c).join(v), s)),
      present.reduce((acc, c) => acc.split(c).join(""), s),
    ]);
  const swapIn = matched
    .slice(0, 12)
    .flatMap((s) => cps.slice(0, 6).map((c) => vocab.reduce((acc, v) => acc.split(v).join(c), s)));
  return [...new Set([...swapOut, ...swapIn])].filter((s) => s.length > 0 && s.length < 4000);
}

/** Deterministic 32-bit LCG so a failure is always reproducible. */
function makeRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

/**
 * The fuzz alphabet must carry BOTH dialects' vocabulary: the codepoints the
 * original names, and the characters the rewrite introduces (`x`, braces, hex
 * digits). Omitting the latter is how a differential test lies by omission --
 * the degraded JS reading of `\\x{0041}` can never be exercised if no input
 * can contain an `x` or a brace.
 */
function fuzzAlphabet(pattern: string, after: string): string[] {
  const cps = referencedCodepoints(pattern).map((cp) => String.fromCodePoint(cp));
  const literals = [...new Set(pattern.match(/[\x20-\x7e]/g) ?? [])];
  const rewriteVocab = [...new Set(after.match(/[\x20-\x7e]/g) ?? [])];
  const spaces = ["\u0020", "\u00a0", "\u2003", "\n", "\t"];
  const wide = ["\u{1F600}", "\u{E0041}", "\uDB40", "\uDC41"];
  return [...new Set([...cps, ...literals, ...rewriteVocab, ...spaces, ...wide])];
}

function fuzzInputs(pattern: string, after: string, count: number, seed: number): string[] {
  const alphabet = fuzzAlphabet(pattern, after);
  const rnd = makeRng(seed);
  return Array.from({ length: count }, () => {
    const len = 1 + Math.floor(rnd() * MAX_FUZZ_LEN);
    return Array.from({ length: len }, () => alphabet[Math.floor(rnd() * alphabet.length)]!).join("");
  });
}

// ---------------------------------------------------------------------------
// RE2 oracle (Go regexp)
// ---------------------------------------------------------------------------

const GO_ORACLE = `package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

type job struct {
	Pattern string   \`json:"pattern"\`
	Inputs  []string \`json:"inputs"\`
}

type result struct {
	OK      bool   \`json:"ok"\`
	Error   string \`json:"error"\`
	Matches string \`json:"matches"\`
}

func main() {
	var jobs []job
	if err := json.NewDecoder(os.Stdin).Decode(&jobs); err != nil {
		os.Exit(2)
	}
	out := make([]result, 0, len(jobs))
	for _, j := range jobs {
		re, err := regexp.Compile(j.Pattern)
		if err != nil {
			out = append(out, result{OK: false, Error: err.Error()})
			continue
		}
		var b strings.Builder
		for _, in := range j.Inputs {
			if re.MatchString(in) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		out = append(out, result{OK: true, Matches: b.String()})
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
`;

interface GoJob {
  readonly pattern: string;
  readonly inputs: readonly string[];
}

interface GoResult {
  readonly ok: boolean;
  readonly error: string;
  readonly matches: string;
}

/** Escape every non-ASCII code unit so lone surrogates survive transport. */
function encodeJobs(jobs: readonly GoJob[]): string {
  return JSON.stringify(jobs).replace(/[\u007f-\uffff]/gu, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function runGo(jobs: readonly GoJob[]): GoResult[] {
  const dir = mkdtempSync(join(tmpdir(), "atr-re2-eq-"));
  const src = join(dir, "main.go");
  writeFileSync(src, GO_ORACLE, "utf8");
  const stdout = execFileSync("go", ["run", src], {
    input: encodeJobs(jobs),
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
  });
  return JSON.parse(stdout) as GoResult[];
}

/** Go has no per-call flags; the ATR engine always compiles case-insensitive. */
function toGoSource(value: string): string {
  return `(?i)${normalizeRegex(value)}`;
}

// ---------------------------------------------------------------------------
// Dialect controls: divergence classes that exist WITHOUT any rewrite
// ---------------------------------------------------------------------------

/**
 * Every one of these patterns is already RE2-legal and contains no `\u`
 * escape, so this script never rewrites them. If JS and RE2 still disagree on
 * them, the disagreement belongs to the JS/RE2 dialect gap, not to the escape
 * rewrite. This turns "that mismatch is pre-existing" from an assertion into a
 * measurement.
 */
interface Control {
  readonly name: string;
  readonly pattern: string;
  readonly input: string;
  readonly why: string;
}

const CONTROLS: readonly Control[] = [
  { name: "whitespace-nbsp", pattern: "a\\sb", input: "a\u00a0b", why: "JS \\s includes U+00A0; RE2 \\s is [\\t\\n\\f\\r ]" },
  { name: "whitespace-emsp", pattern: "a\\sb", input: "a\u2003b", why: "JS \\s includes U+2003; RE2 \\s does not" },
  { name: "dot-granularity", pattern: "^.$", input: "\u{1F600}", why: "JS . is one UTF-16 code unit; RE2 . is one rune" },
  { name: "negclass-granularity", pattern: "^[^a]{1}$", input: "\u{1F600}", why: "negated class counts code units in JS, runes in RE2" },
  { name: "surrogate-coerced", pattern: "^[\\x{DB40}]$", input: "\uDB40", why: "RE2 silently folds a surrogate escape to U+FFFD -- it compiles and matches nothing real" },
  { name: "surrogate-pair-dead", pattern: "^\\x{DB40}[\\x{DC00}-\\x{DC7F}]$", input: "\u{E0000}", why: "a UTF-16 surrogate-pair pattern can never match its own astral codepoint in RE2" },
  { name: "surrogate-pair-fixed", pattern: "^[\\x{E0000}-\\x{E007F}]$", input: "\u{E0000}", why: "the codepoint-range refactor of that same pattern DOES match" },
];

interface ControlResult extends Control {
  readonly js: boolean;
  readonly re2: boolean;
  readonly diverges: boolean;
}

function runControls(): ControlResult[] {
  const results = runGo(CONTROLS.map((c) => ({ pattern: `(?i)${c.pattern}`, inputs: [c.input] })));
  return CONTROLS.map((c, i) => {
    const js = engineCompile(c.pattern)?.test(c.input) ?? false;
    const re2 = results[i]!.ok && results[i]!.matches === "1";
    return { ...c, js, re2, diverges: js !== re2 };
  });
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

interface Verdict {
  readonly ruleId: string;
  readonly file: string;
  readonly location: string;
  readonly before: string;
  readonly after: string;
  readonly inputs: number;
  readonly jsOriginalCompiles: boolean;
  readonly jsRewrittenCompiles: boolean;
  readonly re2RejectsOriginal: boolean;
  readonly re2AcceptsRewrite: boolean;
  readonly engineEquivalent: boolean;
  readonly re2Equivalent: boolean;
  readonly engineMismatches: number;
  readonly re2Mismatches: number;
  readonly engineDiffSamples: readonly string[];
  readonly re2DiffSamples: readonly string[];
  readonly notes: readonly string[];
  readonly re2DivergenceCauses: readonly string[];
}

// ---------------------------------------------------------------------------
// Why a rewritten pattern still behaves differently under RE2
// ---------------------------------------------------------------------------
//
// These causes are dialect gaps that the escape rewrite cannot close: the
// rewrite fixes the SPELLING, but JavaScript and RE2 still disagree about what
// some constructs MEAN. They are only ever attached to a pattern the
// differential run actually caught diverging, so this classification explains
// observed evidence rather than predicting it.

const SURROGATE_ESCAPE = /\\[ux]\{?(D[89AB][0-9A-F]{2})\}?/i;

/** Best-effort cause list for an observed RE2 divergence. Pure. */
function classifyRe2Divergence(before: string, after: string): string[] {
  const causes: string[] = [];
  if (SURROGATE_ESCAPE.test(before)) {
    causes.push(
      "pattern names UTF-16 surrogate codepoints (U+D800-U+DFFF); RE2 has no " +
        "surrogates and folds them to U+FFFD, so the ported pattern compiles but can never match"
    );
  }
  if (/\\[sS]/.test(after)) {
    causes.push(
      "\\s/\\S differ by dialect: JavaScript includes Unicode spaces (U+00A0, U+2003, U+3000, ...), " +
        "RE2 restricts them to ASCII [\\t\\n\\f\\r ]"
    );
  }
  if (/\[\^/.test(after) || /\[\\s\\S\]/.test(after) || /(?:^|[^\\])\./.test(after)) {
    causes.push(
      "any-character constructs count differently: JavaScript without the u flag counts UTF-16 " +
        "code units (an astral character is two), RE2 counts runes (one), so bounded repeats disagree"
    );
  }
  return causes.length > 0
    ? causes
    : ["observed divergence not attributable to a known dialect gap; requires human review"];
}

/** Render an input so an invisible-codepoint divergence is actually readable. */
function showInput(s: string): string {
  const shown = [...s.slice(0, 48)]
    .map((ch) => {
      const cp = ch.codePointAt(0)!;
      return cp >= 0x20 && cp <= 0x7e ? ch : `\\u{${cp.toString(16).toUpperCase()}}`;
    })
    .join("");
  return `"${shown}"${s.length > 48 ? ` (+${s.length - 48} chars)` : ""}`;
}

/** Up to `limit` positions where two match vectors disagree, with the input. */
function diffSamples(a: string, b: string, inputs: readonly string[], limit = 4): string[] {
  const out: string[] = [];
  for (let i = 0; i < Math.min(a.length, b.length) && out.length < limit; i += 1) {
    if (a[i] !== b[i]) out.push(`input#${i} ${showInput(inputs[i]!)} -> ${a[i]} vs ${b[i]}`);
  }
  if (a.length !== b.length) out.push("vector length differs");
  return out;
}

function countDiff(a: string, b: string): number {
  return [...a].reduce((n, ch, i) => (ch === b[i] ? n : n + 1), 0);
}

interface Case {
  readonly ref: PatternRef;
  readonly after: string;
  readonly inputs: readonly string[];
}

function buildBase(shared: readonly string[], fuzzCount: number): Case[] {
  return loadCorpus()
    .map((ref) => ({ ref, rewrite: rewriteForRe2(ref.pattern) }))
    .filter(({ rewrite }) => rewrite.plan.length > 0)
    .map(({ ref, rewrite }, i) => ({
      ref,
      after: rewrite.source,
      inputs: [
        ...shared,
        ...boundaryProbes(ref.pattern),
        ...rewriteArtifactProbes(rewrite.source),
        ...fuzzInputs(ref.pattern, rewrite.source, fuzzCount, 0x5eed + i * 7919),
      ],
    }));
}

/** Inputs either JS arm already matches -- the seeds worth mutating. */
function matchedInputs(c: Case): string[] {
  const before = engineCompile(c.ref.pattern);
  const afterRe = engineCompile(c.after);
  return c.inputs.filter((s) => (before?.test(s) ?? false) || (afterRe?.test(s) ?? false)).slice(0, 24);
}

function buildCases(shared: readonly string[], fuzzCount: number): Case[] {
  return buildBase(shared, fuzzCount).map((c) => ({
    ...c,
    inputs: [...c.inputs, ...mutationProbes(c.ref.pattern, c.after, matchedInputs(c))],
  }));
}

function judge(c: Case, re2Orig: GoResult, re2New: GoResult): Verdict {
  const jsBefore = jsVector(c.ref.pattern, c.inputs);
  const jsAfter = jsVector(c.after, c.inputs);
  const notes: string[] = [];
  if (jsAfter === null) notes.push("rewritten pattern does not compile in JavaScript at all");
  if (!re2Orig.ok) notes.push(`RE2 rejects the original: ${re2Orig.error}`);
  if (!re2New.ok) notes.push(`RE2 rejects the rewrite: ${re2New.error}`);
  const engineEquivalent = jsBefore !== null && jsAfter !== null && jsBefore === jsAfter;
  const re2Equivalent = jsBefore !== null && re2New.ok && jsBefore === re2New.matches;
  return {
    ruleId: c.ref.ruleId,
    file: relative(process.cwd(), c.ref.file),
    location: `detection.conditions[${c.ref.index}].value`,
    before: c.ref.pattern,
    after: c.after,
    inputs: c.inputs.length,
    jsOriginalCompiles: jsBefore !== null,
    jsRewrittenCompiles: jsAfter !== null,
    re2RejectsOriginal: !re2Orig.ok,
    re2AcceptsRewrite: re2New.ok,
    engineEquivalent,
    re2Equivalent,
    engineMismatches: jsBefore !== null && jsAfter !== null ? countDiff(jsBefore, jsAfter) : c.inputs.length,
    re2Mismatches: jsBefore !== null && re2New.ok ? countDiff(jsBefore, re2New.matches) : c.inputs.length,
    engineDiffSamples: jsBefore !== null && jsAfter !== null ? diffSamples(jsBefore, jsAfter, c.inputs) : [],
    re2DiffSamples: jsBefore !== null && re2New.ok ? diffSamples(jsBefore, re2New.matches, c.inputs) : [],
    notes,
    re2DivergenceCauses: re2Equivalent ? [] : classifyRe2Divergence(c.ref.pattern, c.after),
  };
}

function renderControls(controls: readonly ControlResult[]): string[] {
  return [
    "DIALECT CONTROLS -- RE2-legal patterns this script never rewrites",
    ...controls.map(
      (c) =>
        `  ${c.name.padEnd(22)} JS=${c.js ? 1 : 0} RE2=${c.re2 ? 1 : 0}  ${c.diverges ? "DIVERGES" : "agrees  "}  ${c.why}`
    ),
    "",
  ];
}

function renderReport(verdicts: readonly Verdict[], sharedCount: number, controls: readonly ControlResult[]): string {
  const engineOk = verdicts.filter((v) => v.engineEquivalent);
  const re2Ok = verdicts.filter((v) => v.re2Equivalent);
  const line = (v: Verdict): string =>
    `  ${v.ruleId} ${v.location.padEnd(32)} inputs=${String(v.inputs).padStart(5)}  ` +
    `JS=${v.engineEquivalent ? "SAME" : `DIFF(${v.engineMismatches})`}  ` +
    `RE2=${v.re2Equivalent ? "SAME" : `DIFF(${v.re2Mismatches})`}`;
  return [
    "RE2 rewrite equivalence proof -- executed, not argued",
    "=".repeat(78),
    `patterns rewritten            ${verdicts.length}`,
    `shared inputs per pattern     ${sharedCount}`,
    `total match comparisons       ${verdicts.reduce((n, v) => n + v.inputs * 2, 0)}`,
    "",
    `RE2 rejects the ORIGINAL      ${verdicts.filter((v) => v.re2RejectsOriginal).length} / ${verdicts.length}  (control: the problem is real)`,
    `RE2 accepts the REWRITE       ${verdicts.filter((v) => v.re2AcceptsRewrite).length} / ${verdicts.length}`,
    "",
    `JS(before) == JS(after)       ${engineOk.length} / ${verdicts.length}  <- safe to write into rules/`,
    `JS(before) == RE2(after)      ${re2Ok.length} / ${verdicts.length}  <- faithful downstream port`,
    "",
    ...verdicts.map(line),
    "",
    ...renderControls(controls),
    ...verdicts
      .filter((v) => !v.engineEquivalent || !v.re2Equivalent)
      .flatMap((v) => [
        `${v.ruleId} ${v.location}`,
        `  before  ${v.before}`,
        `  after   ${v.after}`,
        ...v.engineDiffSamples.map((d) => `  JS  diverges: ${d}`),
        ...v.re2DiffSamples.map((d) => `  RE2 diverges: ${d}`),
        ...v.notes.map((n) => `  note: ${n}`),
        "",
      ]),
  ].join("\n");
}

/**
 * Persist the executed verdict so the exporters can tag portability from
 * measured behaviour instead of re-deriving engine semantics in another
 * language. scripts/generate-sigma.py reads this file; regenerate it with
 * `--write-equivalence` whenever a rewritten pattern changes.
 */
function writeEquivalenceArtifact(path: string, verdicts: readonly Verdict[]): void {
  const diverging = verdicts.filter((v) => !v.re2Equivalent);
  const byRule = diverging.reduce<Record<string, unknown[]>>(
    (acc, v) => ({
      ...acc,
      [v.ruleId]: [
        ...(acc[v.ruleId] ?? []),
        {
          location: v.location,
          mismatches: v.re2Mismatches,
          inputs: v.inputs,
          causes: v.re2DivergenceCauses,
          examples: v.re2DiffSamples.slice(0, 2),
        },
      ],
    }),
    {}
  );
  writeFileSync(
    path,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        note:
          "Patterns whose mechanical RE2 escape rewrite compiles under RE2 but does NOT reproduce " +
          "the original JavaScript match vector. Produced by scripts/verify-re2-equivalence.ts " +
          "(differential execution, not static analysis). Consumed by scripts/generate-sigma.py " +
          "so a rule that would silently mis-detect on an RE2 backend is tagged, not shipped as clean.",
        patternsRewritten: verdicts.length,
        re2Equivalent: verdicts.length - diverging.length,
        re2Divergent: diverging.length,
        divergentRules: byRule,
      },
      null,
      2
    ) + "\n",
    "utf8"
  );
}

function main(): void {
  const argv = process.argv.slice(2);
  const fuzzArg = argv.indexOf("--samples");
  const fuzzCount = fuzzArg === -1 ? DEFAULT_FUZZ : Number(argv[fuzzArg + 1] ?? DEFAULT_FUZZ);
  const shared = [...new Set([...loadCorpusTestInputs(), ...loadBenignSample()])];
  const cases = buildCases(shared, fuzzCount);
  const re2Orig = runGo(cases.map((c) => ({ pattern: toGoSource(c.ref.pattern), inputs: c.inputs })));
  const re2New = runGo(cases.map((c) => ({ pattern: toGoSource(c.after), inputs: c.inputs })));
  const verdicts = cases.map((c, i) => judge(c, re2Orig[i]!, re2New[i]!));
  const controls = runControls();

  const writeArg = argv.indexOf("--write-equivalence");
  if (writeArg !== -1) {
    const out = resolve(process.cwd(), argv[writeArg + 1] ?? "data/re2-equivalence.json");
    writeEquivalenceArtifact(out, verdicts);
    console.error(`[verify-re2] wrote ${relative(process.cwd(), out)}`);
  }

  if (argv.includes("--json")) {
    process.stdout.write(JSON.stringify({ sharedInputs: shared.length, fuzzCount, controls, verdicts }, null, 2) + "\n");
  } else {
    process.stdout.write(renderReport(verdicts, shared.length, controls) + "\n");
  }
  if (verdicts.some((v) => !v.re2Equivalent)) process.exitCode = 1;
}

main();
