#!/usr/bin/env npx tsx
/**
 * scripts/render-benchmark-table.ts
 *
 * Rewrite the measured cells of README.md's benchmark table, and the
 * `benchmarks.garak` / `.pint` / `.skill` blocks of root `stats.json`, from
 * each source's `data/measurements/<source>/latest.json`.
 *
 * WHY THIS EXISTS
 *
 * scripts/check-benchmark-citations.ts fails CI when README or root stats.json
 * quotes a number no measurement file backs. That check is right, but until
 * now both surfaces were edited by hand, so the weekly measure-all run could
 * only ever produce a PR that check rejects: measurement files moved, README
 * did not (PR #656 — 45 mismatches). This script is the other half of that
 * check. It projects measurements into the citing surfaces; it never decides
 * what a number should be.
 *
 * THE RULE: A NEW STAMP ONLY OVER NUMBERS FROM THAT RUN
 *
 * A row or block whose ATR version / measured date moves is "re-stamped", and
 * everything under the new stamp must come from the new measurement. So on
 * re-stamp each version-bound value is either recomputed from latest.json (and
 * the measurement file it points at) or removed. Nothing is carried over:
 * a 3.5.12 figure under a 4.1.5 stamp reads as a 4.1.5 measurement.
 *
 *   README.md   — for each benchmark-table row the checker maps to a measured,
 *                 non-exempt source: Source version, Samples, Recall,
 *                 Precision, FP rate, ATR version and Measured. When the
 *                 measurement records breakdown.enforce_lane, Recall becomes
 *                 `<hunt> (hunt) / <enforce> (enforce)` plus its footnote
 *                 markers, which is what the checker requires. Otherwise Recall
 *                 keeps the first figure's lane annotation, and any further
 *                 lane figure (`/ 0.0% (enforce)`) is dropped on re-stamp,
 *                 because nothing measured it. Labels, footnotes, row order,
 *                 padding of unchanged cells and every other line stay
 *                 byte-identical. Unmeasured and exempt rows are untouched.
 *   stats.json  — recall / samples / atr_version / measured / precision /
 *                 fpRate / detected / missed / enforceLaneRecall are
 *                 recomputed, and enforceLaneRecall is added after recall to
 *                 a block that lacks it when its measurement records the
 *                 enforce lane; garak.perFamily is recomputed from garak-full's
 *                 by_family when garak-full was measured at the same ATR
 *                 version. Descriptors of the corpus or method — source,
 *                 disclaimer, caveat on every block; lane, tiers,
 *                 notOfficialPint where they apply — are kept byte-for-byte
 *                 and never re-stamped or dropped.
 *                 On re-stamp, DROPPABLE_FIELDS this run cannot derive
 *                 (pint.comment, skill.enforceLaneNote, a perFamily without a
 *                 same-version garak-full) are dropped. A block holding any
 *                 other field — including an enforceLaneRecall this run did
 *                 not record — is left on its old stamp, for the checker to
 *                 fail and a human to classify.
 *
 * A rate is never rounded to 0% when it is not zero, nor to 100% when it is
 * not one; that includes the enforce-lane figure (pctLane), which sits near
 * zero. (The hunt recall keeps the checker's one-decimal form, which CI
 * enforces.)
 *
 * Row -> source mapping, percentage formatting and the table parser are
 * imported from the checker, and the rendered documents are re-checked with
 * it, so the output is by construction what CI accepts.
 *
 * Input is projected from latest.json exactly as sync-stats-from-measurements.ts
 * projects it into data/stats.json — the file the checker compares against. If
 * data/stats.json disagrees with that projection the script stops: rendering
 * from one and checking against the other would guarantee nothing.
 *
 * Usage:
 *   npx tsx scripts/render-benchmark-table.ts                       # rewrite in place
 *   npx tsx scripts/render-benchmark-table.ts --check               # exit 1 if a file would change
 *   npx tsx scripts/render-benchmark-table.ts --root <dir>          # another checkout (tests, CI)
 *   npx tsx scripts/render-benchmark-table.ts --review-notes <file> # what a human should re-read
 *
 * --review-notes writes Markdown for the rolling PR body (empty when there is
 * nothing to check): the README prose and footnote lines near the table that
 * cite a version or percentage, the stats.json fields dropped, and any block
 * left unstamped. See scripts/lib/benchmark-review-notes.ts.
 *
 * Exit codes: 0 = files current (or rewritten). 1 = --check found a file that
 * would change. 2 = cannot render: data/stats.json stale or unreadable input.
 * A citation problem rendering cannot fix (an unmapped row label, a recall
 * cell with no percentage) is printed as a warning in both modes and left to
 * check-benchmark-citations.ts to fail, so a measurement run still pushes.
 */

import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  type BenchmarkEntry,
  EXEMPT_SOURCES,
  LABEL_TO_SOURCE,
  ROOT_BLOCK_SOURCES,
  decimalsFor,
  enforceRecallBySource,
  findCitationProblems,
  parseBenchmarkTable,
  pct1,
  pctLane,
  pctLaneNumber,
} from "./check-benchmark-citations.js";
import { citedTokens, findProseToReview, formatReviewNotes } from "./lib/benchmark-review-notes.js";
import { aggregateMeasurements, projectForStats, type StatsBenchmarkEntry } from "./measurement/aggregate.js";

const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** README column order, as parseBenchmarkTable reads it. */
const COL = {
  sourceVersion: 1,
  samples: 2,
  recall: 3,
  precision: 4,
  fpRate: 5,
  atrVersion: 6,
  measured: 7,
} as const;

// ── numbers ───────────────────────────────────────────────────────────────────

export { decimalsFor };

/** A README rate cell, at the cell's own precision or finer. `0.20%` keeps two decimals. */
function pctCell(cellPct: string, value: number): string {
  const min = /\.(\d+)%$/.exec(cellPct)?.[1].length ?? 0;
  return `${(value * 100).toFixed(decimalsFor(value, min))}%`;
}

/** A stats.json rate, in percent. */
const pctNumber = (value: number, min: number): number => Number((value * 100).toFixed(decimalsFor(value, min)));

// ── README ────────────────────────────────────────────────────────────────────

/** The checker's figure shape: `91.5%`, optionally `91.5% (hunt)`. */
const FIGURE = /(\d+(?:\.\d+)?%)(\s*\([a-z-]+\))?/g;
const FOOTNOTE_REF = /\[\^[^\]]+\]/g;

/** Replace the leading percentage of a cell, keeping whatever surrounds it. */
function replaceLeadingPct(cell: string, render: (old: string) => string): string {
  return cell.replace(/\d+(?:\.\d+)?%/, (old) => render(old));
}

/**
 * The recall cell. When the measurement records an enforce-lane figure the
 * cell is rewritten whole, as `<hunt> (hunt) / <enforce> (enforce)`, keeping
 * only its footnote markers: the checker requires both figures, and any other
 * wording in the cell ("not an enforce figure") would contradict the second.
 *
 * Otherwise the leading figure becomes the measurement (the checker's
 * one-decimal form). On re-stamp, figures after it go — nothing measured a
 * second lane for this row — while the first figure's lane annotation and any
 * footnote markers stay. `100.0% (hunt) / 0.0% (enforce)` -> `95.0% (hunt)`.
 */
function recallCell(cell: string, recall: number, restamp: boolean, enforce: number | undefined): string {
  const figures = [...cell.matchAll(FIGURE)];
  if (figures.length === 0) return cell;
  if (enforce !== undefined) {
    const notes = cell.match(FOOTNOTE_REF) ?? [];
    return [`${pct1(recall)} (hunt) / ${pctLane(enforce)} (enforce)`, ...notes].join(" ");
  }
  if (!restamp || figures.length === 1) return replaceLeadingPct(cell, () => pct1(recall));
  const first = figures[0];
  const firstEnd = (first.index ?? 0) + first[0].length;
  const notes = cell.slice(firstEnd).match(FOOTNOTE_REF) ?? [];
  const head = cell.slice(0, first.index) + pct1(recall) + (first[2] ?? "");
  return [head, ...notes].join(" ");
}

/** The new text of each measured cell for one row, keyed by column index. */
function cellsFor(cells: readonly string[], entry: BenchmarkEntry, enforce: number | undefined): Map<number, string> {
  const measured = entry.measured_at.slice(0, 10);
  const restamp = cells[COL.atrVersion] !== entry.atr_version || cells[COL.measured] !== measured;
  const next = new Map<number, string>([
    [COL.sourceVersion, entry.source_version],
    [COL.samples, entry.samples.toLocaleString("en-US")],
    [COL.atrVersion, entry.atr_version],
    [COL.measured, measured],
  ]);
  const recall = entry.recall;
  // The checker skips a `—` recall cell; so does this.
  if (recall !== null && cells[COL.recall] !== "—") {
    next.set(COL.recall, recallCell(cells[COL.recall], recall, restamp, enforce));
  }
  const precision = entry.precision;
  if (precision !== null) {
    next.set(COL.precision, replaceLeadingPct(cells[COL.precision], (old) => pctCell(old, precision)));
  }
  const fpRate = entry.fp_rate;
  if (fpRate !== null) {
    next.set(COL.fpRate, replaceLeadingPct(cells[COL.fpRate], (old) => pctCell(old, fpRate)));
  }
  return next;
}

/** Tokens a cell cited before and no longer does. */
function replacedTokens(before: string, after: string): string[] {
  const kept = new Set(citedTokens(after));
  return citedTokens(before).filter((t) => !kept.has(t));
}

/** Rewrite one table line, touching only cells whose trimmed text changes. */
function renderRow(
  line: string,
  entry: BenchmarkEntry,
  enforce: number | undefined,
): { line: string; replaced: string[] } {
  // Same split the checker uses; segment i + 1 holds cell i with its padding.
  const segments = line.split("|");
  const cells = segments.slice(1, -1).map((c) => c.trim());
  const next = cellsFor(cells, entry, enforce);
  const replaced: string[] = [];
  const out = segments.map((seg, i) => {
    const value = next.get(i - 1);
    if (value === undefined || value === seg.trim()) return seg;
    replaced.push(...replacedTokens(seg, value));
    return ` ${value} `;
  });
  return { line: out.join("|"), replaced };
}

export interface ReadmeRender {
  text: string;
  /** Versions, percentages and dates the table cited before this render and no longer does. */
  replaced: string[];
}

/**
 * Pure: README text in, README text out, plus what the table stopped citing.
 * Only lines the checker parses as benchmark rows with a mapped, non-exempt,
 * measured source can change. `enforce` is each source's recorded enforce-lane
 * recall (enforceRecallBySource); a row whose source is in it cites both lanes.
 */
export function renderReadmeDetailed(
  readme: string,
  entries: readonly BenchmarkEntry[],
  enforce: ReadonlyMap<string, number> = new Map(),
): ReadmeRender {
  const bySource = new Map(entries.map((e) => [e.source, e]));
  const lines = readme.split("\n");
  const rendered = new Map<number, string>();
  const replaced = new Set<string>();
  for (const row of parseBenchmarkTable(readme)) {
    const source = LABEL_TO_SOURCE.get(row.label);
    if (source === undefined || EXEMPT_SOURCES.has(source)) continue;
    const entry = bySource.get(source);
    if (entry === undefined) continue;
    const idx = row.lineNo - 1;
    const result = renderRow(lines[idx], entry, enforce.get(source));
    rendered.set(idx, result.line);
    for (const t of result.replaced) replaced.add(t);
  }
  return { text: lines.map((l, i) => rendered.get(i) ?? l).join("\n"), replaced: [...replaced] };
}

export function renderReadme(
  readme: string,
  entries: readonly BenchmarkEntry[],
  enforce: ReadonlyMap<string, number> = new Map(),
): string {
  return renderReadmeDetailed(readme, entries, enforce).text;
}

// ── root stats.json ───────────────────────────────────────────────────────────

/**
 * Fields on every rendered block that describe the corpus or the method, never
 * a run: kept byte-for-byte across stamps, never recomputed, never dropped.
 * `disclaimer` and `caveat` hold honesty disclosures outward material quotes
 * ("NOT a run of Lakera's official PINT benchmark ..."); a limitation that
 * depends on a rule count or a measured number belongs in a field a
 * measurement re-derives, not here.
 */
const STABLE_FIELDS: readonly string[] = ["source", "disclaimer", "caveat"];

/** A root stats.json block: which source it cites and which of its fields outlive a stamp. */
interface RootBlockRule {
  readonly source: string;
  /** Block-specific STABLE_FIELDS: describe the corpus or the method, not a run. */
  readonly descriptors: readonly string[];
  /** perFamily is copied from this source's by_family, measured at the same ATR version. */
  readonly perFamilyFrom?: string;
}

/** The checker's block -> source map, so the two can never cite different measurements. */
const sourceOf = (block: string): string => {
  const source = ROOT_BLOCK_SOURCES.get(block);
  if (source === undefined) throw new Error(`ROOT_BLOCK_SOURCES has no "${block}" block`);
  return source;
};

const ROOT_BLOCKS: ReadonlyMap<string, RootBlockRule> = new Map([
  // perFamily has always been garak-full's per-family recall (34.4 / 96.4 / 92.5 at 3.5.12).
  ["garak", { source: sourceOf("garak"), descriptors: ["lane"], perFamilyFrom: "garak-full" }],
  ["pint", { source: sourceOf("pint"), descriptors: ["tiers", "notOfficialPint", "lane"] }],
  ["skill", { source: sourceOf("skill"), descriptors: ["lane"] }],
]);

/**
 * Version-bound fields no measurement file carries: pint.comment counts rules
 * and per-rule detections, and skill.enforceLaneNote is prose around a figure.
 * Dropped when their block is re-stamped. The limitations they stated outside
 * those numbers live on in the blocks' `disclaimer` / `caveat` (STABLE_FIELDS).
 *
 * `enforceLaneRecall` is not here: every runner records the enforce lane as
 * breakdown.enforce_lane, so it is re-derived like recall. Nor is it optional:
 * it is the disclosure beside the headline, so a block citing one that this
 * run did not record is held on its old stamp for a human, never stripped.
 */
const UNMEASURED_FIELDS: ReadonlyMap<string, readonly string[]> = new Map([
  ["pint", ["comment"]],
  ["skill", ["enforceLaneNote"]],
]);

/**
 * Fields a measurement can re-derive but not every run does: detected/missed
 * need a confusion matrix, perFamily needs garak-full at the same version. On
 * re-stamp, one this run could not derive is dropped, never carried over.
 */
const OPTIONAL_DERIVED = ["precision", "fpRate", "detected", "missed", "perFamily"] as const;

/**
 * Every field a re-stamp may remove, per block. Dropping is safe only while
 * nothing reads them — README badges, sync-stats.ts, the website and the
 * checker read recall / samples / atr_version / measured / rules /
 * lastUpdated — and tests/render-benchmark-table.test.ts fails if a reader
 * appears.
 */
export const DROPPABLE_FIELDS: ReadonlyMap<string, readonly string[]> = new Map(
  [...ROOT_BLOCKS].map(([key, rule]) => [
    key,
    [
      ...(UNMEASURED_FIELDS.get(key) ?? []),
      ...OPTIONAL_DERIVED.filter((f) => f !== "perFamily" || rule.perFamilyFrom !== undefined),
    ],
  ]),
);

/** What a measurement file adds to its latest.json pointer. */
export interface MeasurementDetail {
  /** Confusion-matrix true positives / false negatives. */
  detected?: number;
  missed?: number;
  /** Recall per probe family, 0-1, keyed as the measurement keys it. */
  byFamily?: Readonly<Record<string, number>>;
}

type Block = Readonly<Record<string, unknown>>;

const snakeCase = (key: string) => key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** The block's perFamily, re-derived for its existing keys, or undefined when it cannot be. */
function perFamilyFor(
  existing: unknown,
  entry: BenchmarkEntry,
  family: BenchmarkEntry | undefined,
  detail: MeasurementDetail | undefined,
): Record<string, number> | undefined {
  const byFamily = detail?.byFamily;
  if (!isRecord(existing) || family === undefined || byFamily === undefined) return undefined;
  if (family.atr_version !== entry.atr_version) return undefined;
  const out: Record<string, number> = {};
  for (const key of Object.keys(existing)) {
    const recall = byFamily[key] ?? byFamily[snakeCase(key)];
    if (recall === undefined) return undefined;
    out[key] = pctNumber(recall, 1);
  }
  return out;
}

/** Every field this run's measurements can re-derive for a block. */
function computedFields(
  cite: Block,
  entry: BenchmarkEntry & { recall: number },
  rule: RootBlockRule,
  bySource: ReadonlyMap<string, BenchmarkEntry>,
  details: ReadonlyMap<string, MeasurementDetail>,
  enforce: number | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    // The checker's own projection of a recall.
    recall: Number((entry.recall * 100).toFixed(1)),
    samples: entry.samples,
    atr_version: entry.atr_version,
    measured: entry.measured_at.slice(0, 10),
  };
  if (entry.precision !== null) out.precision = pctNumber(entry.precision, 1);
  if (entry.fp_rate !== null) out.fpRate = pctNumber(entry.fp_rate, 2);
  // The checker's own projection of an enforce figure (never 0 when it is not).
  if (enforce !== undefined) out.enforceLaneRecall = pctLaneNumber(enforce);
  const detail = details.get(entry.source);
  if (detail?.detected !== undefined) out.detected = detail.detected;
  if (detail?.missed !== undefined) out.missed = detail.missed;
  if (rule.perFamilyFrom !== undefined) {
    const from = rule.perFamilyFrom;
    const perFamily = perFamilyFor(cite.perFamily, entry, bySource.get(from), details.get(from));
    if (perFamily !== undefined) out.perFamily = perFamily;
  }
  return out;
}

interface BlockRender {
  cite: Block;
  dropped: string[];
  held: string[];
}

function renderBlock(
  key: string,
  cite: Block,
  rule: RootBlockRule,
  bySource: ReadonlyMap<string, BenchmarkEntry>,
  details: ReadonlyMap<string, MeasurementDetail>,
  enforce: ReadonlyMap<string, number>,
): BlockRender {
  const entry = bySource.get(rule.source);
  if (entry === undefined || entry.recall === null) return { cite, dropped: [], held: [] };
  const computed = computedFields(
    cite,
    { ...entry, recall: entry.recall },
    rule,
    bySource,
    details,
    enforce.get(rule.source),
  );
  const restamp =
    (cite.atr_version !== undefined && cite.atr_version !== computed.atr_version) ||
    (cite.measured !== undefined && cite.measured !== computed.measured);
  const recompute = ([k, v]: [string, unknown]): [string, unknown] => [k, k in computed ? computed[k] : v];
  if (!restamp) {
    return { cite: withEnforceFigure(Object.fromEntries(Object.entries(cite).map(recompute)), computed), dropped: [], held: [] };
  }

  const droppable = DROPPABLE_FIELDS.get(key) ?? [];
  const stable = (k: string) => STABLE_FIELDS.includes(k) || rule.descriptors.includes(k);
  const keys = Object.keys(cite).filter((k) => !(k in computed) && !stable(k));
  const unknown = keys.filter((k) => !droppable.includes(k));
  if (unknown.length > 0) {
    return {
      cite,
      dropped: [],
      held: [
        `benchmarks.${key} kept its ${String(cite.atr_version ?? cite.measured)} stamp: no rule for ` +
          `${unknown.join(", ")}. Recompute or classify it in scripts/render-benchmark-table.ts.`,
      ],
    };
  }
  const next = Object.entries(cite)
    .filter(([k]) => !keys.includes(k))
    .map(recompute);
  return {
    cite: withEnforceFigure(Object.fromEntries(next), computed),
    dropped: keys.map((k) => `benchmarks.${key}.${k}`),
    held: [],
  };
}

/**
 * The one field a render adds rather than only rewriting: a block whose
 * measurement records the enforce lane cites it, right after its recall, as
 * the checker requires — the hunt figure must not travel alone from the file
 * sync-stats.ts propagates.
 */
function withEnforceFigure(block: Record<string, unknown>, computed: Record<string, unknown>): Block {
  if (!("enforceLaneRecall" in computed) || "enforceLaneRecall" in block) return block;
  const entries = Object.entries(block);
  const at = entries.findIndex(([k]) => k === "recall") + 1;
  const insertAt = at === 0 ? entries.length : at;
  return Object.fromEntries([
    ...entries.slice(0, insertAt),
    ["enforceLaneRecall", computed.enforceLaneRecall],
    ...entries.slice(insertAt),
  ]);
}

export interface RootStatsRender {
  stats: Record<string, unknown>;
  /** Fields removed on re-stamp, as `benchmarks.<block>.<field>`. */
  dropped: string[];
  /** Blocks left on their old stamp, with the reason. */
  held: string[];
}

/**
 * Pure: root stats.json object in, new object out. Only the blocks in
 * ROOT_BLOCKS change, and key order is preserved, so the file diff is the
 * changed values and removed fields. Only keys a block already has are
 * written, with one exception: enforceLaneRecall is added, after recall, to a
 * block whose measurement records the enforce lane (withEnforceFigure).
 */
export function renderRootStats(
  rootStats: Readonly<Record<string, unknown>>,
  entries: readonly BenchmarkEntry[],
  details: ReadonlyMap<string, MeasurementDetail> = new Map(),
  /** Recorded enforce-lane recall per source (enforceRecallBySource). */
  enforce: ReadonlyMap<string, number> = new Map(),
): RootStatsRender {
  const benchmarks = rootStats.benchmarks;
  if (!isRecord(benchmarks)) return { stats: { ...rootStats }, dropped: [], held: [] };
  const bySource = new Map(entries.map((e) => [e.source, e]));
  const dropped: string[] = [];
  const held: string[] = [];
  const nextBenchmarks = Object.fromEntries(
    Object.entries(benchmarks).map(([key, cite]) => {
      const rule = ROOT_BLOCKS.get(key);
      if (rule === undefined || !isRecord(cite)) return [key, cite];
      const result = renderBlock(key, cite, rule, bySource, details, enforce);
      dropped.push(...result.dropped);
      held.push(...result.held);
      return [key, result.cite];
    }),
  );
  return { stats: { ...rootStats, benchmarks: nextBenchmarks }, dropped, held };
}

// ── the checkout ──────────────────────────────────────────────────────────────

export interface RepoRender {
  readme: { path: string; before: string; after: string };
  rootStats: { path: string; before: string; after: string };
  /** What the citation check still reports on the rendered documents (normally none). */
  residual: string[];
  /** stats.json blocks left on their old stamp. */
  held: string[];
  /** Markdown for the rolling PR body; "" when nothing needs a human. */
  notes: string;
}

function readText(path: string): string {
  if (!existsSync(path)) throw new Error(`${path} does not exist`);
  return readFileSync(path, "utf-8");
}

/** Confusion counts and per-family recall from the measurement files the root blocks cite. */
function measurementDetails(root: string, entries: readonly StatsBenchmarkEntry[]): Map<string, MeasurementDetail> {
  const wanted = new Set(
    [...ROOT_BLOCKS.values()].flatMap((r) => (r.perFamilyFrom === undefined ? [r.source] : [r.source, r.perFamilyFrom])),
  );
  const out = new Map<string, MeasurementDetail>();
  for (const e of entries) {
    if (!wanted.has(e.source)) continue;
    const m = JSON.parse(readText(resolve(root, e.measurement_file))) as {
      confusion?: { tp?: unknown; fn?: unknown };
      breakdown?: { by_family?: unknown };
    };
    const { tp, fn } = m.confusion ?? {};
    const rawFamilies = m.breakdown?.by_family;
    const families = isRecord(rawFamilies) ? Object.entries(rawFamilies) : [];
    const byFamily = Object.fromEntries(
      families.flatMap(([k, v]): [string, number][] =>
        isRecord(v) && typeof v.recall === "number" ? [[k, v.recall]] : [],
      ),
    );
    out.set(e.source, {
      ...(typeof tp === "number" && typeof fn === "number" ? { detected: tp, missed: fn } : {}),
      ...(families.length > 0 ? { byFamily } : {}),
    });
  }
  return out;
}

/**
 * Render README.md and stats.json under `root` in memory. Throws when
 * data/stats.json is not the projection of the latest.json pointers. Whatever
 * the citation check still reports on the rendered text — a row whose label it
 * does not map, a recall cell with no percentage — is returned in `residual`:
 * those need a human, and rendering cannot fix them.
 */
export function renderRepo(root: string): RepoRender {
  const agg = aggregateMeasurements(resolve(root, "data", "measurements"));
  for (const b of agg.sources_broken) {
    console.error(`WARNING: ${b.source} latest.json is broken (${b.reason}); its row is left as is.`);
  }
  const entries = projectForStats(agg).benchmarks;

  const dataStatsPath = resolve(root, "data", "stats.json");
  const dataStats = JSON.parse(readText(dataStatsPath)) as { benchmarks?: BenchmarkEntry[] };
  if (JSON.stringify(dataStats.benchmarks ?? null) !== JSON.stringify(entries)) {
    throw new Error(
      "data/stats.json benchmarks[] is not the projection of data/measurements/*/latest.json. " +
        "Run `npx tsx scripts/sync-stats-from-measurements.ts` first — the citation check " +
        "compares against data/stats.json, so rendering from anything else proves nothing.",
    );
  }

  const readmePath = resolve(root, "README.md");
  const rootStatsPath = resolve(root, "stats.json");
  const readmeBefore = readText(readmePath);
  const rootStatsBefore = readText(rootStatsPath);
  // The checker reads the same breakdown.enforce_lane records, the same way.
  const enforce = enforceRecallBySource(root, entries);
  const readme = renderReadmeDetailed(readmeBefore, entries, enforce);
  const rootStats = renderRootStats(
    JSON.parse(rootStatsBefore) as Record<string, unknown>,
    entries,
    measurementDetails(root, entries),
    enforce,
  );
  // An unchanged object keeps the file's own bytes, whatever its formatting.
  const rootStatsAfter =
    JSON.stringify(JSON.parse(rootStatsBefore)) === JSON.stringify(rootStats.stats)
      ? rootStatsBefore
      : JSON.stringify(rootStats.stats, null, 2) + "\n";

  const check = findCitationProblems(readme.text, dataStats, rootStats.stats, enforce);
  const notes = formatReviewNotes({
    prose: readme.text === readmeBefore ? [] : findProseToReview(readme.text, readme.replaced),
    dropped: rootStats.dropped,
    held: rootStats.held,
  });

  return {
    readme: { path: readmePath, before: readmeBefore, after: readme.text },
    rootStats: { path: rootStatsPath, before: rootStatsBefore, after: rootStatsAfter },
    residual: check.fatal !== null ? [check.fatal] : check.problems,
    held: rootStats.held,
    notes,
  };
}

function flagValue(argv: readonly string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} needs a value`);
  return value;
}

function main(argv: readonly string[]): number {
  const check = argv.includes("--check");
  let result: RepoRender;
  let notesPath: string | undefined;
  try {
    notesPath = flagValue(argv, "--review-notes");
    result = renderRepo(resolve(flagValue(argv, "--root") ?? DEFAULT_ROOT));
  } catch (err) {
    console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
  // Not fatal in either mode: they are the citation check's to fail, not this
  // script's. The measure-all run must still push its measurements, and the
  // PR's citation check then fails where a human sees it.
  for (const p of [...result.residual, ...result.held]) {
    console.error(`::warning::rendered, but needs a human: ${p}`);
  }
  if (notesPath !== undefined) writeFileSync(notesPath, result.notes);

  const changed = [result.readme, result.rootStats].filter((f) => f.before !== f.after);
  if (check) {
    for (const f of changed) console.error(`STALE: ${f.path} differs from data/measurements/`);
    if (changed.length > 0) console.error("Run `npx tsx scripts/render-benchmark-table.ts` to re-render.");
    if (changed.length > 0) return 1;
    console.log("README.md and stats.json match data/measurements/.");
    return 0;
  }
  if (changed.length === 0) {
    console.log("benchmark citations already match data/measurements/ — nothing to render.");
    return 0;
  }
  for (const f of changed) {
    writeFileSync(f.path, f.after);
    console.log(`rendered ${f.path}`);
  }
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
