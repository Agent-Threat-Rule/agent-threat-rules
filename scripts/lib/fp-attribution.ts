/**
 * The attribution report of a delta re-measure, and the PR-body section made
 * from it.
 *
 * WHY THIS EXISTS
 *
 * A benign sample can only ever take a rule's block actions away: if a rule
 * fires on it, the rule's measured false-positive rate rises and the
 * response-action gate lowers what the rule may do. So a poisoned "benign"
 * sample is a way to switch a detection off, and the samples the weekly
 * harvest adds are third-party text. When the gate fails on a harvest, the
 * question for the reviewer is not "which rules do I demote" but "do the
 * samples that trigger them belong in the corpus at all". That question needs
 * the samples named, per rule. This module carries them from
 * scripts/remeasure-benign-fp.ts (which writes the report) to the PR body
 * (scripts/render-fp-attribution.ts renders it).
 *
 * THE TEXT IS UNTRUSTED
 *
 * Every string that came out of a sample — excerpt, source, source_id, even
 * the file name — is flattened to one line, has its control, zero-width and
 * bidi characters escaped visibly, is capped in length, and is rendered only
 * inside a fenced code block whose fence is longer than any backtick run in
 * the content. Inside a code block GitHub renders no links, images or HTML and
 * resolves no @-mentions, so a sample cannot ping anyone, hide text or reshape
 * the body a reviewer reads.
 */

export const ATTRIBUTION_SCHEMA = "atr/benign-fp-attribution@1" as const;

/** Where one newly added copy of a sample sits in the head corpus. */
export interface SampleLocation {
  readonly file: string;
  /** 1-based line of a .jsonl record; null for a .md file, which is one sample. */
  readonly line: number | null;
  readonly source: string | null;
  readonly source_id: string | null;
}

export interface AttributedSample {
  readonly excerpt: string;
  /** How many of the added samples carry exactly this text (the corpus is a multiset). */
  readonly occurrences: number;
  /** Where the newly added copies of this text sit in the head corpus. */
  readonly locations: readonly SampleLocation[];
}

/** "delta": base count plus this harvest's matches. "full": re-measured over the whole corpus. */
export type MeasuredBy = "delta" | "full";

export interface AttributedRule {
  readonly id: string;
  readonly measured: MeasuredBy;
  /** The committed count, or null when the base evidence has no record of the rule. */
  readonly fp_count_before: number | null;
  readonly fp_count_after: number;
  /** Matches among the added samples, counted per sample exactly like fp_count. */
  readonly added_matches: number;
  readonly samples: readonly AttributedSample[];
}

export type FullReason =
  | "absent-from-base-evidence"
  | "detection-changed"
  | "not-loadable"
  | "unusable-base-record";

export interface FullMeasurement {
  readonly id: string;
  readonly reason: FullReason;
}

export interface AttributionReport {
  readonly schema: typeof ATTRIBUTION_SCHEMA;
  readonly base_ref: string;
  readonly base_commit: string;
  readonly base_sample_count: number;
  readonly added_sample_count: number;
  readonly head_sample_count: number;
  readonly rules_total: number;
  readonly measured_on_added_only: number;
  readonly measured_in_full: readonly FullMeasurement[];
  /** Every rule that fires on at least one added sample, sorted by id. */
  readonly rules: readonly AttributedRule[];
}

/** One rule the response-action gate fails, as `gate-action-eligibility.ts --json` names it. */
export interface GateViolation {
  readonly id: string;
  readonly unearned: readonly string[];
  readonly reason: string | null;
}

export interface RenderCaps {
  /** Rule blocks shown in the PR body, across both lists; failing rules first. */
  readonly maxRules: number;
  readonly maxSamplesPerRule: number;
}

/** Sized so the section stays under ~30k characters whatever the harvest holds. */
export const DEFAULT_CAPS: RenderCaps = Object.freeze({ maxRules: 15, maxSamplesPerRule: 4 });

export const EXCERPT_CHARS = 140;
const SOURCE_CHARS = 32;
const SOURCE_ID_CHARS = 64;
const FILE_CHARS = 96;
const REASON_CHARS = 200;

const FULL_REASON_TEXT: Readonly<Record<FullReason, string>> = Object.freeze({
  "absent-from-base-evidence": "absent from the committed evidence",
  "detection-changed": "detection changed since it",
  "not-loadable": "not loadable by the engine",
  "unusable-base-record": "unusable record in it",
});

// ---------------------------------------------------------------------------
// Untrusted text
// ---------------------------------------------------------------------------

// C0/C1 controls, zero-width and joiner characters, bidi embeddings/overrides/
// isolates, the BOM — and lone surrogates, which do not survive UTF-8.
const INVISIBLE =
  /[\u0000-\u001f\u007f-\u009f­​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

/**
 * One line of display text from untrusted input: whitespace runs collapse to a
 * space, invisible characters become visible `\u{..}` escapes, and the result
 * is cut to `max` code points with a trailing "…". Idempotent on its own output.
 */
export function sanitizeInline(text: string, max: number): string {
  const flat = text
    .replace(/\s+/g, " ")
    .trim()
    .replace(INVISIBLE, (c) => `\\u{${(c.codePointAt(0) ?? 0).toString(16)}}`);
  const points = Array.from(flat);
  return points.length > max ? `${points.slice(0, max).join("")}…` : flat;
}

// ---------------------------------------------------------------------------
// Parsing (the report crosses a process boundary; check it, do not trust it)
// ---------------------------------------------------------------------------

type Obj = Readonly<Record<string, unknown>>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isCount = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0;
const isStrOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";

function fail(what: string): never {
  throw new Error(`attribution report: ${what}`);
}

function parseLocation(v: unknown): SampleLocation {
  if (!isObj(v)) fail("a sample location is not an object");
  const { file, line, source, source_id: sourceId } = v;
  if (typeof file !== "string") fail("a sample location has no file");
  if (!(line === null || (Number.isInteger(line) && (line as number) > 0))) fail(`bad line in ${file}`);
  if (!isStrOrNull(source) || !isStrOrNull(sourceId)) fail(`bad source in ${file}`);
  return { file, line: line as number | null, source, source_id: sourceId };
}

function parseSample(v: unknown): AttributedSample {
  if (!isObj(v)) fail("a sample is not an object");
  if (typeof v.excerpt !== "string") fail("a sample has no excerpt");
  if (!isCount(v.occurrences) || v.occurrences === 0) fail("a sample has no occurrences");
  if (!Array.isArray(v.locations)) fail("a sample has no locations");
  return { excerpt: v.excerpt, occurrences: v.occurrences, locations: v.locations.map(parseLocation) };
}

function parseRule(v: unknown): AttributedRule {
  if (!isObj(v) || typeof v.id !== "string") fail("a rule entry has no id");
  const { id, measured, fp_count_before: before, fp_count_after: after, added_matches: added } = v;
  if (measured !== "delta" && measured !== "full") fail(`${id}: bad "measured"`);
  if (!(before === null || isCount(before)) || !isCount(after) || !isCount(added)) fail(`${id}: bad counts`);
  if (!Array.isArray(v.samples)) fail(`${id}: no samples`);
  const samples = v.samples.map(parseSample);
  const total = samples.reduce((n, s) => n + s.occurrences, 0);
  if (total !== added) fail(`${id}: ${total} sample occurrence(s) listed for ${added} match(es)`);
  return { id, measured, fp_count_before: before, fp_count_after: after, added_matches: added, samples };
}

function parseFull(v: unknown): FullMeasurement {
  if (!isObj(v) || typeof v.id !== "string") fail("a measured_in_full entry has no id");
  if (typeof v.reason !== "string" || !(v.reason in FULL_REASON_TEXT)) fail(`${v.id}: bad reason`);
  return { id: v.id, reason: v.reason as FullReason };
}

export function parseAttributionReport(raw: string): AttributionReport {
  const v = JSON.parse(raw) as unknown;
  if (!isObj(v)) fail("not an object");
  if (v.schema !== ATTRIBUTION_SCHEMA) fail(`schema is ${String(v.schema)}, expected ${ATTRIBUTION_SCHEMA}`);
  for (const k of [
    "base_sample_count",
    "added_sample_count",
    "head_sample_count",
    "rules_total",
    "measured_on_added_only",
  ]) {
    if (!isCount(v[k])) fail(`${k} is not a count`);
  }
  if (typeof v.base_ref !== "string" || typeof v.base_commit !== "string") fail("no base");
  if (!Array.isArray(v.measured_in_full) || !Array.isArray(v.rules)) fail("no rule lists");
  return {
    schema: ATTRIBUTION_SCHEMA,
    base_ref: v.base_ref,
    base_commit: v.base_commit,
    base_sample_count: v.base_sample_count as number,
    added_sample_count: v.added_sample_count as number,
    head_sample_count: v.head_sample_count as number,
    rules_total: v.rules_total as number,
    measured_on_added_only: v.measured_on_added_only as number,
    measured_in_full: v.measured_in_full.map(parseFull),
    rules: v.rules.map(parseRule),
  };
}

/**
 * The violations `gate-action-eligibility.ts --json` printed. An empty file is
 * null, not []: the gate exits 1 without printing JSON when it fails on
 * something other than unearned actions (a message_template claim), and "no
 * rules named" must not read as "no rules failed".
 */
export function parseGateViolations(raw: string): readonly GateViolation[] | null {
  if (raw.trim() === "") return null;
  const v = JSON.parse(raw) as unknown;
  if (!isObj(v) || !Array.isArray(v.violations)) throw new Error("gate output has no violations list");
  return v.violations.map((x: unknown): GateViolation => {
    if (!isObj(x) || typeof x.id !== "string") throw new Error("a gate violation has no id");
    const unearned = Array.isArray(x.unearned) ? x.unearned.filter((a): a is string => typeof a === "string") : [];
    const reason = isObj(x.decision) && typeof x.decision.reason === "string" ? x.decision.reason : null;
    return { id: x.id, unearned, reason: typeof x.reason === "string" ? x.reason : reason };
  });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

function summaryLine(r: AttributionReport): string {
  const why = new Map<FullReason, number>();
  for (const f of r.measured_in_full) why.set(f.reason, (why.get(f.reason) ?? 0) + 1);
  const reasons = [...why].map(([k, n]) => `${n} ${FULL_REASON_TEXT[k]}`).join(", ");
  const full = r.measured_in_full.length;
  return (
    `Re-measured by scripts/remeasure-benign-fp.ts against ${r.base_ref} (${r.base_commit.slice(0, 12)}): ` +
    `${r.measured_on_added_only} of ${r.rules_total} rules on the ${plural(r.added_sample_count, "new sample")} ` +
    `only (their detection is unchanged since the committed evidence), ${full} in full` +
    `${full > 0 ? ` (${reasons})` : ""}. ` +
    `${plural(r.rules.length, "rule fires", "rules fire")} on at least one new sample.`
  );
}

function locationLine(l: SampleLocation, occurrences: number): string {
  const tag = [l.source, l.source_id]
    .map((s, i) => (s === null ? null : sanitizeInline(s, i === 0 ? SOURCE_CHARS : SOURCE_ID_CHARS)))
    .filter((s): s is string => s !== null && s !== "")
    .join(" ");
  const where = `${sanitizeInline(l.file, FILE_CHARS)}${l.line === null ? "" : `:${l.line}`}`;
  const times = occurrences > 1 ? `  (x${occurrences} among the new samples)` : "";
  return `  - ${tag === "" ? "(no source recorded)" : tag}  ${where}${times}`;
}

function sampleLines(s: AttributedSample): readonly string[] {
  const first = s.locations[0];
  const head = first === undefined ? "  - (location unknown)" : locationLine(first, s.occurrences);
  const more = s.locations.slice(1).map((l) => `    also ${locationLine(l, 1).slice(4)}`);
  return [head, ...more, `      "${sanitizeInline(s.excerpt, EXCERPT_CHARS)}"`];
}

function ruleLines(
  id: string,
  rule: AttributedRule | undefined,
  violation: GateViolation | undefined,
  maxSamples: number,
): readonly string[] {
  const out: string[] = [];
  if (rule === undefined) {
    out.push(`${sanitizeInline(id, 40)}  no new sample fires on it: this failure does not come from this harvest`);
  } else {
    const before = rule.fp_count_before === null ? "unmeasured" : String(rule.fp_count_before);
    const how = rule.measured === "full" ? ", re-measured in full" : "";
    out.push(
      `${sanitizeInline(rule.id, 40)}  fp_count ${before} -> ${rule.fp_count_after} ` +
        `(+${rule.added_matches} from the new samples${how})`,
    );
  }
  if (violation !== undefined) {
    const unearned = violation.unearned.map((a) => sanitizeInline(a, 40)).join(", ");
    const reason = violation.reason === null ? "" : ` -- ${sanitizeInline(violation.reason, REASON_CHARS)}`;
    out.push(`    gate: unearned: ${unearned === "" ? "(not listed)" : unearned}${reason}`);
  }
  const samples = rule?.samples ?? [];
  for (const s of samples.slice(0, maxSamples)) out.push(...sampleLines(s));
  if (samples.length > maxSamples) {
    out.push(`  … ${plural(samples.length - maxSamples, "more new sample")} for this rule`);
  }
  return out;
}

/** A fence longer than any backtick run in the content, so no content line can close it. */
function fenced(lines: readonly string[]): string {
  // reduce, not Math.max(...spread): the uncapped log can hold more lines than a call takes arguments.
  const longest = lines.reduce(
    (max, l) => (l.match(/`+/g) ?? []).reduce((m, run) => Math.max(m, run.length), max),
    0,
  );
  const fence = "`".repeat(Math.max(3, longest + 1));
  return [`${fence}text`, ...lines, fence].join("\n");
}

interface Listing {
  readonly title: string;
  readonly ids: readonly string[];
}

function listings(report: AttributionReport, violations: readonly GateViolation[] | null | undefined): Listing[] {
  const failing = [...new Set((violations ?? []).map((v) => v.id))];
  const failingSet = new Set(failing);
  const others = [...report.rules]
    .filter((r) => !failingSet.has(r.id))
    .sort((a, b) => b.added_matches - a.added_matches || a.id.localeCompare(b.id))
    .map((r) => r.id);
  if (failing.length === 0) return [{ title: "Rules that fire on the new samples:", ids: others }];
  return [
    { title: "Rules the response-action gate now fails, and the new samples each one fires on:", ids: failing },
    { title: "Other rules that fire on the new samples (their actions stay within what the evidence earns):", ids: others },
  ];
}

function renderListings(
  report: AttributionReport,
  violations: readonly GateViolation[] | null | undefined,
  caps: RenderCaps,
): string[] {
  const rules = new Map(report.rules.map((r) => [r.id, r]));
  const byViolation = new Map((violations ?? []).map((v) => [v.id, v]));
  const out: string[] = [];
  let budget = caps.maxRules;
  for (const { title, ids } of listings(report, violations)) {
    if (ids.length === 0) continue;
    const shown = ids.slice(0, Math.max(0, budget));
    budget -= shown.length;
    const lines = shown.flatMap((id) => ruleLines(id, rules.get(id), byViolation.get(id), caps.maxSamplesPerRule));
    if (ids.length > shown.length) lines.push(`… ${plural(ids.length - shown.length, "more rule")}`);
    out.push(title, "", fenced(lines), "");
  }
  return out;
}

/**
 * The PR-body section (`markdown`, capped) and the same listing uncapped
 * (`log`, for the job log, which every "… N more" points at).
 *
 * `violations`: the gate's --json output. `undefined` when the gate passed (no
 * file was produced); `null` when it failed without naming rules.
 */
export function renderAttributionSection(
  report: AttributionReport,
  violations: readonly GateViolation[] | null | undefined,
  caps: RenderCaps = DEFAULT_CAPS,
): { readonly markdown: string; readonly log: string } {
  const head = [summaryLine(report), ""];
  if (violations === null) {
    head.push("The gate failed without naming rules with unearned actions; its output is below.", "");
  }
  const none = report.rules.length === 0 && (violations ?? []).length === 0;
  const tail = none ? ["No rule fires on any of the new samples.", ""] : null;
  const uncapped: RenderCaps = { maxRules: Number.MAX_SAFE_INTEGER, maxSamplesPerRule: Number.MAX_SAFE_INTEGER };
  const build = (c: RenderCaps): string => [...head, ...(tail ?? renderListings(report, violations, c))].join("\n");
  return { markdown: build(caps), log: build(uncapped) };
}
