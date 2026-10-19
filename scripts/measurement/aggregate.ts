/**
 * scripts/measurement/aggregate.ts
 *
 * Reads every `latest.json` under `data/measurements/<source>/` and produces
 * an aggregate suitable for embedding in `stats.json`, README badges, or the
 * website's `lib/stats.ts`.
 *
 * Pure read; no writes. Callers compose this with `sync-stats-from-measurements.ts`
 * to update on-disk artifacts.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { type LatestPointer, parseLatestPointer } from "../../src/measurement/schema.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");
const MEASUREMENTS_DIR = resolve(REPO_ROOT, "data", "measurements");

/** Aggregate snapshot of all known sources' latest measurements. */
export interface MeasurementsAggregate {
  /** Generation timestamp (ISO 8601 UTC). */
  generated_at: string;
  /** Per-source latest pointer, keyed by source name. */
  sources: Record<string, LatestPointer>;
  /** Sources that have a directory but no parseable `latest.json` yet. */
  sources_pending: string[];
  /** Sources where `latest.json` exists but failed schema validation. */
  sources_broken: { source: string; reason: string }[];
  /**
   * Sources whose measurement file declares `breakdown.precision_not_citable`:
   * too few benign samples for a precision or FP-rate claim. Their precision,
   * F1 and FP rate are projected as null, not as the bare ratio.
   */
  precision_not_citable: string[];
}

/** The breakdown key a measurement uses to say its precision / FP rate must not be cited. */
export const PRECISION_NOT_CITABLE_KEY = "precision_not_citable";

function declaresPrecisionNotCitable(sourceDir: string, file: string): boolean {
  const path = join(sourceDir, file);
  if (!existsSync(path)) return false;
  const m = JSON.parse(readFileSync(path, "utf-8")) as { breakdown?: Record<string, unknown> };
  return m.breakdown?.[PRECISION_NOT_CITABLE_KEY] !== undefined;
}

/**
 * Load and aggregate all `latest.json` pointers.
 *
 * Throws on filesystem I/O errors. Schema-violating pointers are reported in
 * `sources_broken` rather than throwing; this lets callers proceed with
 * partial data and surface broken sources for human triage.
 *
 * `measurementsDir` defaults to this repo's `data/measurements/`; tests point
 * it at a fixture tree.
 */
export function aggregateMeasurements(measurementsDir: string = MEASUREMENTS_DIR): MeasurementsAggregate {
  const out: MeasurementsAggregate = {
    generated_at: new Date().toISOString(),
    sources: {},
    sources_pending: [],
    sources_broken: [],
    precision_not_citable: [],
  };

  if (!existsSync(measurementsDir)) return out;

  for (const entry of readdirSync(measurementsDir)) {
    const sourceDir = join(measurementsDir, entry);
    if (!statSync(sourceDir).isDirectory()) continue;
    const latest = join(sourceDir, "latest.json");
    if (!existsSync(latest)) {
      out.sources_pending.push(entry);
      continue;
    }
    try {
      const raw = JSON.parse(readFileSync(latest, "utf-8")) as unknown;
      const pointer = parseLatestPointer(raw);
      out.sources[entry] = pointer;
      if (declaresPrecisionNotCitable(sourceDir, pointer.file)) out.precision_not_citable.push(entry);
    } catch (err) {
      out.sources_broken.push({
        source: entry,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return out;
}

/**
 * Render an aggregate as a Markdown table fit for embedding in the README.
 * Columns: Source, Version, Samples, Recall, Precision, FP rate, Measured.
 */
export function aggregateAsMarkdown(agg: MeasurementsAggregate): string {
  const rows = Object.entries(agg.sources)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([_name, p]) => {
      const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
      const date = p.measured_at.slice(0, 10);
      return `| ${p.source} | ${p.source_version} | ${p.samples} | ${pct(p.metrics.recall)} | ${pct(p.metrics.precision)} | ${pct(p.metrics.fp_rate)} | ${date} |`;
    });
  if (rows.length === 0) {
    return "_No measurements yet._\n";
  }
  return [
    "| Source | Version | Samples | Recall | Precision | FP rate | Measured |",
    "|---|---|---:|---:|---:|---:|---|",
    ...rows,
    "",
  ].join("\n");
}

/**
 * Project a `MeasurementsAggregate` into the shape that the website's
 * `lib/stats.ts` will consume, and that `stats.json` carries verbatim.
 *
 * Output schema:
 * ```
 * {
 *   "generated_at": "...",
 *   "benchmarks": [
 *     {
 *       "source": "garak",
 *       "source_version": "v0.10.3",
 *       "atr_version": "3.0.0-alpha.0",
 *       "measured_at": "2026-04-21",
 *       "samples": 666,
 *       "recall": 0.971,
 *       "precision": 1.0,
 *       "f1": 0.9853,
 *       "fp_rate": 0,
 *       "measurement_file": "data/measurements/garak/2026-04-21_..."
 *     },
 *     ...
 *   ]
 * }
 * ```
 */
export interface StatsBenchmarkEntry {
  source: string;
  source_version: string;
  atr_version: string;
  measured_at: string;
  samples: number;
  recall: number;
  /** null when the measurement declares breakdown.precision_not_citable. */
  precision: number | null;
  f1: number | null;
  fp_rate: number | null;
  measurement_file: string;
}

export interface StatsBenchmarksProjection {
  generated_at: string;
  benchmarks: StatsBenchmarkEntry[];
}

export function projectForStats(agg: MeasurementsAggregate): StatsBenchmarksProjection {
  const benchmarks: StatsBenchmarkEntry[] = Object.entries(agg.sources)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, p]) => {
      const citable = !(agg.precision_not_citable ?? []).includes(name);
      return {
        source: p.source,
        source_version: p.source_version,
        atr_version: p.atr_version,
        measured_at: p.measured_at.slice(0, 10),
        samples: p.samples,
        recall: p.metrics.recall,
        precision: citable ? p.metrics.precision : null,
        f1: citable ? p.metrics.f1 : null,
        fp_rate: citable ? p.metrics.fp_rate : null,
        measurement_file: `data/measurements/${p.source}/${p.file}`,
      };
    });
  return { generated_at: agg.generated_at, benchmarks };
}
