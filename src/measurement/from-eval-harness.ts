/**
 * src/measurement/from-eval-harness.ts
 *
 * Adapter: convert an `src/eval/eval-harness.ts` `EvalReport` into a
 * `MeasurementInput`. Used by the four first-class eval runners (PINT,
 * HackAPrompt, atr-self-test, the SKILL.md runner) to write a Measurement
 * file at the end of an eval run without each runner duplicating the
 * conversion logic.
 *
 * The shape of `EvalReport` is defined in `src/eval/eval-harness.ts`; we
 * accept a structurally-typed input here to avoid creating a cross-module
 * type dependency in either direction.
 */

import { writeMeasurement, type MeasurementInput } from "./write.js";

/**
 * Structural type matching the fields we read from `EvalReport`. Kept here so
 * `src/eval/*` does not need to export its internal types just to use the
 * adapter.
 */
export interface EvalHarnessReportShape {
  timestamp?: string;
  corpusSize: number;
  overall: {
    recall: number;
    precision: number;
    f1: number;
    fpRate: number;
    confusion: { tp: number; fp: number; tn: number; fn: number };
    sampleCount?: number;
  };
  latency?: { p50: number; p95: number; p99: number; mean: number; max: number };
  byCategory?: unknown;
  byDifficulty?: unknown;
}

export interface FromEvalHarnessOpts {
  /** Source identifier (lowercase, hyphenated). Example: "pint". */
  source: string;
  /** Source version. Example: "v1", "corpus-2026-05-20". */
  source_version: string;
  /** Optional canonical upstream URL. */
  source_url?: string;
  /** Optional human-readable context. */
  notes?: string;
  /**
   * Force overwrite if the same filename already exists (same source +
   * source_version + atr_version + date). Defaults to false (append-only).
   */
  force?: boolean;
}

/**
 * Build a `MeasurementInput` from an `EvalReport` plus source metadata, then
 * write it via `writeMeasurement()`. Returns the same paths/objects that
 * `writeMeasurement()` returns.
 */
export function writeMeasurementFromEvalReport(
  report: EvalHarnessReportShape,
  opts: FromEvalHarnessOpts,
) {
  const input: MeasurementInput = {
    source: opts.source,
    source_version: opts.source_version,
    measured_at: report.timestamp,
    samples: report.corpusSize,
    metrics: {
      recall: report.overall.recall,
      precision: report.overall.precision,
      f1: report.overall.f1,
      fp_rate: report.overall.fpRate,
    },
    confusion: report.overall.confusion,
  };
  if (opts.source_url) input.source_url = opts.source_url;
  if (opts.notes) input.notes = opts.notes;
  if (report.latency) input.latency_ms = report.latency;
  const breakdown: Record<string, unknown> = {};
  if (report.byCategory) breakdown.by_category = report.byCategory;
  if (report.byDifficulty) breakdown.by_difficulty = report.byDifficulty;
  if (Object.keys(breakdown).length > 0) input.breakdown = breakdown;
  return writeMeasurement(input, { force: opts.force ?? true });
}
