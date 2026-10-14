#!/usr/bin/env npx tsx
/**
 * scripts/render-benchmark-table.ts
 *
 * Rewrite the measured cells of README.md's benchmark table, and the
 * `benchmarks.garak` / `benchmarks.pint` citations in root `stats.json`, from
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
 * What it touches, and nothing else:
 *   README.md   — for each benchmark-table row whose label the checker maps to
 *                 a source with a latest.json: Source version, Samples, Recall
 *                 (the leading percentage only — lane annotations and any
 *                 second-lane figure are kept), Precision, FP rate, ATR version
 *                 and Measured. Row order, labels, footnote markers, padding of
 *                 unchanged cells and every other line stay byte-identical.
 *                 Rows without a measurement, and checker-exempt rows
 *                 (wild-scan), are left as they are.
 *   stats.json  — the keys the checker reads (recall, samples, atr_version,
 *                 measured) plus the siblings derived from the same run
 *                 (detected, missed, precision, fpRate), for garak and pint,
 *                 and only keys that already exist.
 *
 * Row -> source mapping, percentage formatting and the table parser are
 * imported from the checker, and --check re-runs the checker over the
 * rendered text, so the output is by construction what CI accepts.
 *
 * Input is projected from latest.json exactly as sync-stats-from-measurements.ts
 * projects it into data/stats.json — the file the checker compares against. If
 * data/stats.json disagrees with that projection the script stops: rendering
 * from one and checking against the other would guarantee nothing.
 *
 * Usage:
 *   npx tsx scripts/render-benchmark-table.ts                # rewrite in place
 *   npx tsx scripts/render-benchmark-table.ts --check        # exit 1 if a file would change
 *   npx tsx scripts/render-benchmark-table.ts --root <dir>   # another checkout (tests)
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
  findCitationProblems,
  parseBenchmarkTable,
  pct1,
} from "./check-benchmark-citations.js";
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

/** Root stats.json keys the checker reads, and the source each one cites. */
const ROOT_STATS_SOURCES: ReadonlyMap<string, string> = new Map([
  ["garak", "garak"],
  ["pint", "pint"],
]);

/** True-positive / false-negative counts, from the measurement file's confusion matrix. */
export interface DetectionCounts {
  detected: number;
  missed: number;
}

/** `95.2%` stays two-decimal-free, `0.20%` keeps two decimals: the cell's own precision. */
function formatLikeCell(cellPct: string, value: number): string {
  const decimals = /\.(\d+)%$/.exec(cellPct)?.[1].length ?? 0;
  return `${(value * 100).toFixed(decimals)}%`;
}

/**
 * Replace the leading percentage of a cell, keeping lane annotations, a second
 * lane's figure and footnote markers. A cell with no percentage (`—`,
 * `not measured`) is returned unchanged.
 */
function replaceLeadingPct(cell: string, render: (old: string) => string): string {
  return cell.replace(/\d+(?:\.\d+)?%/, (old) => render(old));
}

/** The new text of each measured cell for one row, keyed by column index. */
function cellsFor(cells: readonly string[], entry: BenchmarkEntry): Map<number, string> {
  const next = new Map<number, string>([
    [COL.sourceVersion, entry.source_version],
    [COL.samples, entry.samples.toLocaleString("en-US")],
    [COL.atrVersion, entry.atr_version],
    [COL.measured, entry.measured_at.slice(0, 10)],
  ]);
  const recall = entry.recall;
  // The checker skips a `—` recall cell; so does this.
  if (recall !== null && cells[COL.recall] !== "—") {
    next.set(COL.recall, replaceLeadingPct(cells[COL.recall], () => pct1(recall)));
  }
  const precision = entry.precision;
  if (precision !== null) {
    next.set(COL.precision, replaceLeadingPct(cells[COL.precision], (old) => formatLikeCell(old, precision)));
  }
  const fpRate = entry.fp_rate;
  if (fpRate !== null) {
    next.set(COL.fpRate, replaceLeadingPct(cells[COL.fpRate], (old) => formatLikeCell(old, fpRate)));
  }
  return next;
}

/** Rewrite one table line, touching only cells whose trimmed text changes. */
function renderRow(line: string, entry: BenchmarkEntry): string {
  // Same split the checker uses; segment i + 1 holds cell i with its padding.
  const segments = line.split("|");
  const cells = segments.slice(1, -1).map((c) => c.trim());
  const next = cellsFor(cells, entry);
  const out = segments.map((seg, i) => {
    const value = next.get(i - 1);
    return value === undefined || value === seg.trim() ? seg : ` ${value} `;
  });
  return out.join("|");
}

/**
 * Pure: README text in, README text out. Only lines the checker parses as
 * benchmark rows with a mapped, non-exempt, measured source can change.
 */
export function renderReadme(readme: string, entries: readonly BenchmarkEntry[]): string {
  const bySource = new Map(entries.map((e) => [e.source, e]));
  const lines = readme.split("\n");
  const replaced = new Map<number, string>();
  for (const row of parseBenchmarkTable(readme)) {
    const source = LABEL_TO_SOURCE.get(row.label);
    if (source === undefined || EXEMPT_SOURCES.has(source)) continue;
    const entry = bySource.get(source);
    if (entry === undefined) continue;
    const idx = row.lineNo - 1;
    replaced.set(idx, renderRow(lines[idx], entry));
  }
  return lines.map((l, i) => replaced.get(i) ?? l).join("\n");
}

type RootCite = Record<string, unknown>;

function updateExisting(cite: RootCite, updates: Readonly<Record<string, unknown>>): RootCite {
  const present = Object.entries(updates).filter(([k]) => k in cite);
  return { ...cite, ...Object.fromEntries(present) };
}

/**
 * Pure: root stats.json object in, new object out. Only keys that already
 * exist under benchmarks.garak / benchmarks.pint are rewritten; key order is
 * preserved, so the file diff is the changed values.
 */
export function renderRootStats(
  rootStats: Readonly<Record<string, unknown>>,
  entries: readonly BenchmarkEntry[],
  counts: ReadonlyMap<string, DetectionCounts> = new Map(),
): Record<string, unknown> {
  const benchmarks = rootStats.benchmarks as Record<string, RootCite> | undefined;
  if (benchmarks === undefined) return { ...rootStats };
  const bySource = new Map(entries.map((e) => [e.source, e]));
  const nextBenchmarks = Object.fromEntries(
    Object.entries(benchmarks).map(([key, cite]) => {
      const source = ROOT_STATS_SOURCES.get(key);
      const entry = source === undefined ? undefined : bySource.get(source);
      if (entry === undefined || entry.recall === null) return [key, cite];
      const updates: Record<string, unknown> = {
        // The checker's own projection: Number((recall * 100).toFixed(1)).
        recall: Number((entry.recall * 100).toFixed(1)),
        samples: entry.samples,
        atr_version: entry.atr_version,
        measured: entry.measured_at.slice(0, 10),
        ...(entry.precision === null ? {} : { precision: Number((entry.precision * 100).toFixed(1)) }),
        ...(entry.fp_rate === null ? {} : { fpRate: Number((entry.fp_rate * 100).toFixed(2)) }),
        ...(counts.get(entry.source) ?? {}),
      };
      return [key, updateExisting(cite, updates)];
    }),
  );
  return { ...rootStats, benchmarks: nextBenchmarks };
}

export interface RepoRender {
  readme: { path: string; before: string; after: string };
  rootStats: { path: string; before: string; after: string };
  /** What the citation check still reports on the rendered documents (normally none). */
  residual: string[];
}

function readText(path: string): string {
  if (!existsSync(path)) throw new Error(`${path} does not exist`);
  return readFileSync(path, "utf-8");
}

/** tp / fn from each measurement file, for the root stats.json detected / missed. */
function detectionCounts(root: string, entries: readonly StatsBenchmarkEntry[]): Map<string, DetectionCounts> {
  const out = new Map<string, DetectionCounts>();
  for (const e of entries) {
    if (![...ROOT_STATS_SOURCES.values()].includes(e.source)) continue;
    const m = JSON.parse(readText(resolve(root, e.measurement_file))) as { confusion?: { tp?: unknown; fn?: unknown } };
    const { tp, fn } = m.confusion ?? {};
    if (typeof tp === "number" && typeof fn === "number") out.set(e.source, { detected: tp, missed: fn });
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
  const readmeAfter = renderReadme(readmeBefore, entries);
  const rootStatsObj = renderRootStats(
    JSON.parse(rootStatsBefore) as Record<string, unknown>,
    entries,
    detectionCounts(root, entries),
  );
  const rootStatsAfter = JSON.stringify(rootStatsObj, null, 2) + "\n";
  // An unchanged object keeps the file's own bytes, whatever its formatting.
  const rootStatsOut =
    JSON.stringify(JSON.parse(rootStatsBefore)) === JSON.stringify(rootStatsObj) ? rootStatsBefore : rootStatsAfter;

  const check = findCitationProblems(readmeAfter, dataStats, rootStatsObj);

  return {
    readme: { path: readmePath, before: readmeBefore, after: readmeAfter },
    rootStats: { path: rootStatsPath, before: rootStatsBefore, after: rootStatsOut },
    residual: check.fatal !== null ? [check.fatal] : check.problems,
  };
}

function parseRoot(argv: readonly string[]): string {
  const i = argv.indexOf("--root");
  if (i === -1) return DEFAULT_ROOT;
  const dir = argv[i + 1];
  if (dir === undefined || dir.startsWith("--")) throw new Error("--root needs a directory");
  return resolve(dir);
}

function main(argv: readonly string[]): number {
  const check = argv.includes("--check");
  let result: RepoRender;
  try {
    result = renderRepo(parseRoot(argv));
  } catch (err) {
    console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
  // Not fatal in either mode: they are the citation check's to fail, not this
  // script's. The measure-all run must still push its measurements, and the
  // PR's citation check then fails where a human sees it.
  for (const p of result.residual) {
    console.error(`::warning::rendered, but scripts/check-benchmark-citations.ts still reports: ${p}`);
  }
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
