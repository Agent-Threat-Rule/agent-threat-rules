#!/usr/bin/env npx tsx
/**
 * scripts/render-recall-citations.ts
 *
 * Render the recall figures that Markdown documents outside README quote, from
 * the measurement file each source's `data/measurements/<source>/latest.json`
 * points at.
 *
 * WHY THIS EXISTS
 *
 * README's benchmark table is rendered and checked (render-benchmark-table.ts,
 * check-benchmark-citations.ts), but LIMITATIONS.md and the docs that quote the
 * same corpora were edited by hand. They quoted the hunt lane alone ("100%
 * recall" on SKILL.md, where the enforce lane detects none of the 32 attacks),
 * and their version stamps stayed at 3.5.12 while the measurements moved on.
 * Recall depends on the lane: a figure that does not name its lane, or that
 * leaves out the enforce figure the measurement records, misleads anyone who
 * deploys with blocking on.
 *
 * MARKERS
 *
 *   <!-- recall:<source>[:<format>] -->…<!-- /recall -->
 *
 * Everything between the two comments is replaced and nothing outside them
 * moves. GitHub does not render the comments. <format> defaults to `lanes`:
 *
 *   lanes       65.4% (hunt) / 0.4% (enforce)    the README cell form: every
 *               rendering is held to checkRecallCell, the rule README's table
 *               is checked by; hunt only when the measurement predates the
 *               enforce record
 *   counts      295 of 451 (hunt) / 2 of 451 (enforce)
 *   stamp       ATR 4.1.5, measured 2026-10-15
 *   file        `data/measurements/<source>/<file>.json`
 *   samples     850        attacks  451        benign  399
 *   precision   100.0% (hunt)        f1  79.1% (hunt)
 *   fp-rate     0.20% (hunt)         fp-counts  1 of 466 (hunt)
 *   categories  a per-category recall table (hunt lane) with the overall
 *               enforce figure beside it: no measurement records a
 *               per-category enforce split
 *
 * Precision, F1 and false-positive figures are measured in the hunt lane only,
 * and say so.
 *
 * The documents are listed in DOCUMENTS. A listed document with no marker is a
 * failure: a list entry that renders nothing is how a document stops being
 * checked.
 *
 * Usage:
 *   npx tsx scripts/render-recall-citations.ts               # rewrite in place
 *   npx tsx scripts/render-recall-citations.ts --check       # exit 1 if stale or unrenderable
 *   npx tsx scripts/render-recall-citations.ts --root <dir>  # another checkout (tests, CI)
 *   npx tsx scripts/render-recall-citations.ts --review-notes <file>
 *                                     # append what it could not render (the rolling PR body)
 *
 * Exit codes: 0 = current (or rewritten). 1 = --check found a stale figure or
 * a marker it cannot render. 2 = cannot run. In write mode a marker it cannot
 * render is printed as a warning, listed in --review-notes and left as it is,
 * so the weekly measurement run still pushes; the PR's --check then fails
 * where a human sees it.
 */

import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { checkRecallCell, decimalsFor, pct1, pctLane } from "./check-benchmark-citations.js";
import { appendReviewNotes } from "./lib/append-review-notes.js";
import {
  ENFORCE_LANE_BREAKDOWN_KEY,
  type Confusion,
  type EnforceLaneRecall,
  parseEnforceLaneRecall,
  parseLatestPointer,
  parseMeasurement,
} from "../src/measurement/schema.js";

const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The Markdown documents whose recall figures this script renders and checks. */
export const DOCUMENTS: readonly string[] = [
  "LIMITATIONS.md",
  "docs/owasp-pr/README.md",
  "docs/owasp-pr/ASI01_Agent_Behaviour_Hijack.md",
];

export interface CategoryRecall {
  category: string;
  attacks: number;
  detected: number;
  recall: number;
}

/** What a citation can quote from one measurement file. */
export interface LaneMeasurement {
  source: string;
  /** Repo-relative path of the measurement file latest.json points at. */
  file: string;
  atrVersion: string;
  /** YYYY-MM-DD. */
  measuredDate: string;
  samples: number;
  /** metrics.recall: the hunt lane. */
  recall: number;
  precision: number;
  f1: number;
  fpRate: number;
  confusion: Confusion | null;
  /** breakdown.enforce_lane, or null when the measurement predates it. */
  enforce: EnforceLaneRecall | null;
  byCategory: CategoryRecall[] | null;
}

// ── loading ──────────────────────────────────────────────────────────────────

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf-8"));
}

/** breakdown.by_category as the PINT runner writes it, or null when absent or malformed. */
function categoriesOf(raw: unknown): CategoryRecall[] | null {
  if (!Array.isArray(raw)) return null;
  const out: CategoryRecall[] = [];
  for (const entry of raw as { category?: unknown; metrics?: { confusion?: { tp?: unknown; fn?: unknown } } }[]) {
    const tp = entry.metrics?.confusion?.tp;
    const fn = entry.metrics?.confusion?.fn;
    if (typeof entry.category !== "string" || typeof tp !== "number" || typeof fn !== "number") return null;
    out.push({ category: entry.category, attacks: tp + fn, detected: tp, recall: tp + fn === 0 ? 0 : tp / (tp + fn) });
  }
  return out;
}

/**
 * Load the measurement `data/measurements/<source>/latest.json` points at.
 * Every figure comes from that file, not from the pointer's mirror of it.
 * Throws when either file is missing or fails the measurement schema.
 */
export function loadLaneMeasurement(root: string, source: string): LaneMeasurement {
  const pointerPath = resolve(root, "data", "measurements", source, "latest.json");
  if (!existsSync(pointerPath)) throw new Error(`data/measurements/${source}/latest.json does not exist`);
  const pointer = parseLatestPointer(readJson(pointerPath));
  if (pointer.file.includes("/") || pointer.file.includes("\\")) {
    throw new Error(`data/measurements/${source}/latest.json names "${pointer.file}", which is not a file in that directory`);
  }
  const file = `data/measurements/${source}/${pointer.file}`;
  if (!existsSync(resolve(root, file))) throw new Error(`latest.json points at ${file}, which does not exist`);
  const m = parseMeasurement(readJson(resolve(root, file)));
  const lane = m.breakdown?.[ENFORCE_LANE_BREAKDOWN_KEY];
  return {
    source,
    file,
    atrVersion: m.atr_version,
    measuredDate: m.measured_at.slice(0, 10),
    samples: m.samples,
    recall: m.metrics.recall,
    precision: m.metrics.precision,
    f1: m.metrics.f1,
    fpRate: m.metrics.fp_rate,
    confusion: m.confusion ?? null,
    enforce: lane === undefined ? null : parseEnforceLaneRecall(lane),
    byCategory: categoriesOf(m.breakdown?.by_category),
  };
}

// ── formats ──────────────────────────────────────────────────────────────────

const count = (n: number): string => n.toLocaleString("en-US");

/** A rate that never reads 0% when it is not zero, nor 100% when it is not one. */
const pctAt = (v: number, min: number): string => `${(v * 100).toFixed(decimalsFor(v, min))}%`;

function confusionOf(m: LaneMeasurement): Confusion {
  if (m.confusion === null) throw new Error(`${m.source}: the measurement records no confusion matrix`);
  return m.confusion;
}

function lanes(m: LaneMeasurement): string {
  const hunt = `${pct1(m.recall)} (hunt)`;
  const cell = m.enforce === null ? hunt : `${hunt} / ${pctLane(m.enforce.recall)} (enforce)`;
  const problem = checkRecallCell(cell, m.recall, m.enforce?.recall ?? null);
  if (problem !== null) throw new Error(`${m.source}: rendered a figure README's check would reject: ${problem}`);
  return cell;
}

function counts(m: LaneMeasurement): string {
  const c = confusionOf(m);
  const hunt = `${count(c.tp)} of ${count(c.tp + c.fn)} (hunt)`;
  return m.enforce === null ? hunt : `${hunt} / ${count(m.enforce.detected)} of ${count(m.enforce.attacks)} (enforce)`;
}

const capitalise = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

function categories(m: LaneMeasurement): string {
  if (m.byCategory === null) throw new Error(`${m.source}: the measurement records no breakdown.by_category`);
  const rows = m.byCategory
    .filter((c) => c.attacks > 0)
    .map((c) => `| ${capitalise(c.category)} | ${count(c.attacks)} | ${pct1(c.recall)} |`);
  const enforce =
    m.enforce === null
      ? "This measurement records no `enforce`-lane figure."
      : "The measurement records no per-category split for the `enforce` lane; overall it detects " +
        `${count(m.enforce.detected)} of ${count(m.enforce.attacks)} (${pctLane(m.enforce.recall)}).`;
  return ["", "", "| Category | Attack samples | Recall (hunt) |", "|---|---:|---:|", ...rows, "", enforce, "", ""].join("\n");
}

type Format = (m: LaneMeasurement) => string;

const FORMATS: ReadonlyMap<string, Format> = new Map<string, Format>([
  ["lanes", lanes],
  ["counts", counts],
  ["stamp", (m) => `ATR ${m.atrVersion}, measured ${m.measuredDate}`],
  ["file", (m) => `\`${m.file}\``],
  ["samples", (m) => count(m.samples)],
  ["attacks", (m) => count(confusionOf(m).tp + confusionOf(m).fn)],
  ["benign", (m) => count(confusionOf(m).tn + confusionOf(m).fp)],
  ["precision", (m) => `${pctAt(m.precision, 1)} (hunt)`],
  ["f1", (m) => `${pctAt(m.f1, 1)} (hunt)`],
  ["fp-rate", (m) => `${pctAt(m.fpRate, 2)} (hunt)`],
  ["fp-counts", (m) => `${count(confusionOf(m).fp)} of ${count(confusionOf(m).tn + confusionOf(m).fp)} (hunt)`],
  ["categories", categories],
]);

/** Render one figure. Throws on an unknown format or one the measurement cannot back. */
export function renderFigure(m: LaneMeasurement, format: string): string {
  const render = FORMATS.get(format);
  if (render === undefined) {
    throw new Error(`unknown format "${format}" (known: ${[...FORMATS.keys()].join(", ")})`);
  }
  return render(m);
}

// ── markers ──────────────────────────────────────────────────────────────────

export interface Span {
  source: string;
  format: string;
  body: string;
  /** Offsets of the body, between the two markers. */
  bodyStart: number;
  bodyEnd: number;
}

// `[^\s>]`, not `\S`: a compact `<!--recall:pint-->` must end at its own `-->`.
const TOKEN = /<!--\s*(\/?)recall(?::([^\s>]*))?\s*-->/g;
const SPEC = /^([a-z0-9][a-z0-9-]*)(?::([a-z0-9-]+))?$/;

const lineAt = (text: string, index: number): number => text.slice(0, index).split("\n").length;

/** Parse every marker pair; an opener left unclosed or a stray closer is a problem. */
export function parseSpans(text: string): { spans: Span[]; problems: string[] } {
  const spans: Span[] = [];
  const problems: string[] = [];
  let open: { spec: string; index: number; bodyStart: number } | null = null;
  for (const t of text.matchAll(TOKEN)) {
    const index = t.index ?? 0;
    if (t[1] === "/") {
      if (open === null) {
        problems.push(`line ${lineAt(text, index)}: a closing <!-- /recall --> has no opening marker`);
        continue;
      }
      const spec = SPEC.exec(open.spec);
      if (spec === null) problems.push(`line ${lineAt(text, open.index)}: cannot read marker "recall:${open.spec}"`);
      else spans.push({ source: spec[1], format: spec[2] ?? "lanes", body: text.slice(open.bodyStart, index), bodyStart: open.bodyStart, bodyEnd: index });
      open = null;
      continue;
    }
    if (open !== null) problems.push(`line ${lineAt(text, open.index)}: marker "recall:${open.spec}" is not closed before the next one`);
    open = { spec: t[2] ?? "", index, bodyStart: index + t[0].length };
  }
  if (open !== null) problems.push(`line ${lineAt(text, open.index)}: marker "recall:${open.spec}" is not closed`);
  return { spans, problems };
}

export function findSpans(text: string): Span[] {
  return parseSpans(text).spans;
}

export interface DocumentRender {
  text: string;
  problems: string[];
  spans: number;
}

/** Re-render every span in `text`. A span it cannot back is reported and left as it is. */
export function renderDocument(text: string, load: (source: string) => LaneMeasurement): DocumentRender {
  const { spans, problems: parseProblems } = parseSpans(text);
  const rendered = spans.map((s): { value: string } | { problem: string } => {
    try {
      return { value: renderFigure(load(s.source), s.format) };
    } catch (err) {
      return { problem: `recall:${s.source}:${s.format}: ${err instanceof Error ? err.message : String(err)}` };
    }
  });
  const pieces = spans.map((s, i) => {
    const r = rendered[i];
    const previousEnd = i === 0 ? 0 : spans[i - 1].bodyEnd;
    return text.slice(previousEnd, s.bodyStart) + ("value" in r ? r.value : s.body);
  });
  const tail = text.slice(spans.length === 0 ? 0 : spans[spans.length - 1].bodyEnd);
  return {
    text: pieces.join("") + tail,
    problems: [...parseProblems, ...rendered.flatMap((r) => ("problem" in r ? [r.problem] : []))],
    spans: spans.length,
  };
}

// ── repository ───────────────────────────────────────────────────────────────

export interface FileRender {
  path: string;
  before: string;
  after: string;
}

function memoised(root: string): (source: string) => LaneMeasurement {
  const cache = new Map<string, LaneMeasurement | Error>();
  return (source) => {
    if (!cache.has(source)) {
      try {
        cache.set(source, loadLaneMeasurement(root, source));
      } catch (err) {
        cache.set(source, err instanceof Error ? err : new Error(String(err)));
      }
    }
    const hit = cache.get(source);
    if (hit instanceof Error) throw hit;
    return hit as LaneMeasurement;
  };
}

/** Render every document under `root`, in memory. */
export function renderRepoDocuments(
  root: string,
  documents: readonly string[] = DOCUMENTS,
): { files: FileRender[]; problems: string[] } {
  const load = memoised(root);
  const files: FileRender[] = [];
  const problems: string[] = [];
  for (const doc of documents) {
    const path = resolve(root, doc);
    if (!existsSync(path)) {
      problems.push(`${doc}: does not exist; restore it or remove it from DOCUMENTS`);
      continue;
    }
    const before = readFileSync(path, "utf-8");
    const r = renderDocument(before, load);
    if (r.spans === 0) problems.push(`${doc}: has no recall marker; add one or remove it from DOCUMENTS`);
    problems.push(...r.problems.map((p) => `${doc}: ${p}`));
    files.push({ path, before, after: r.text });
  }
  return { files, problems };
}

function flagValue(argv: readonly string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} needs a value`);
  return value;
}

function main(argv: readonly string[]): number {
  let root: string;
  let notes: string | undefined;
  let result: { files: FileRender[]; problems: string[] };
  try {
    root = resolve(flagValue(argv, "--root") ?? DEFAULT_ROOT);
    notes = flagValue(argv, "--review-notes");
    result = renderRepoDocuments(root);
  } catch (err) {
    console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
  const changed = result.files.filter((f) => f.before !== f.after);
  if (argv.includes("--check")) {
    for (const p of result.problems) console.error(`FAIL: ${p}`);
    for (const f of changed) console.error(`STALE: ${relative(root, f.path)} quotes a figure that differs from data/measurements/`);
    if (result.problems.length + changed.length === 0) {
      console.log(`recall citations OK: ${result.files.length} documents match data/measurements/`);
      return 0;
    }
    if (changed.length > 0) console.error("Run `npx tsx scripts/render-recall-citations.ts` to re-render them.");
    return 1;
  }
  for (const p of result.problems) console.error(`::warning::recall citation needs a human: ${p}`);
  if (notes !== undefined) {
    appendReviewNotes(
      notes,
      "Recall citations not re-rendered",
      "scripts/render-recall-citations.ts left these as they were; CI's --check fails until they are fixed:",
      result.problems,
    );
  }
  for (const f of changed) {
    writeFileSync(f.path, f.after);
    console.log(`rendered ${relative(root, f.path)}`);
  }
  if (changed.length === 0) console.log("recall citations already match data/measurements/; nothing to render.");
  return 0;
}

// Real paths on both sides: a script run through a symlink (or macOS's /tmp)
// sees its own URL resolved while argv keeps the path it was called by.
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
