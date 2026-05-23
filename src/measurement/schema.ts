/**
 * src/measurement/schema.ts
 *
 * Schema for ATR benchmark measurement files.
 *
 * Every public ATR recall / precision / FP-rate claim must reference a
 * measurement file conforming to this schema. The contract is documented in
 * `data/measurements/README.md`.
 *
 * Design constraints:
 *   - No external dependencies (no zod, no ajv). Schemas evolve slowly; the
 *     dependency surface should not.
 *   - Strict at the boundary. `parseMeasurement()` throws on any deviation;
 *     it does not silently coerce, drop fields, or accept missing required
 *     fields.
 *   - Forward-compatible. `schema_version` is mandatory. Future readers can
 *     decide how to handle older versions.
 */

// ─── Schema version ─────────────────────────────────────────────────────────

/** Bump this when the schema breaks backward compatibility. */
export const CURRENT_SCHEMA_VERSION = "1" as const;

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Core metrics that every measurement reports.
 *
 * `recall` is the most-cited number externally. `precision` and `fp_rate`
 * anchor the recall claim against overclaim risk.
 */
export interface Metrics {
  /** True-positive rate. matched_attacks / total_attacks. Range [0, 1]. */
  recall: number;
  /** matched / (matched + false_positives). Range [0, 1]. */
  precision: number;
  /** 2 * precision * recall / (precision + recall). Range [0, 1]. */
  f1: number;
  /** false_positives / total_benign. Range [0, 1]. May be 0 if the corpus has no benign samples. */
  fp_rate: number;
}

/** Confusion matrix. Strongly recommended; CI does not require it. */
export interface Confusion {
  /** True positives — adversarial sample matched by a rule. */
  tp: number;
  /** False positives — benign sample matched by a rule. */
  fp: number;
  /** True negatives — benign sample NOT matched by any rule. */
  tn: number;
  /** False negatives — adversarial sample NOT matched (the recall gap). */
  fn: number;
}

/** Engine latency profile in milliseconds. Optional. */
export interface LatencyMs {
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  max: number;
}

/**
 * Source-defined bespoke breakdown. Each source uses this shape differently:
 *   - garak: by attack family (dan, latentinjection, sysprompt_extraction, …)
 *   - skill-benchmark: by layer (layer_a, layer_b, layer_c)
 *   - mega-scan: by severity (critical, high, medium, low)
 *   - eval-harness: by category and by difficulty
 *
 * Kept as `Record<string, unknown>` because the structure is source-defined.
 * Consumers of this field must validate per-source.
 */
export type Breakdown = Record<string, unknown>;

/**
 * A single measurement run.
 *
 * Required fields are the minimum for a public-citable claim.
 */
export interface Measurement {
  /** Schema version. Currently `"1"`. */
  schema_version: typeof CURRENT_SCHEMA_VERSION;

  /** Stable source identifier. Lowercase, hyphen-separated. Example: `"garak"`, `"pint"`, `"hh-rlhf"`. */
  source: string;

  /** Upstream version. Example: `"v0.10.3"`, `"corpus-2026-04-15"`. */
  source_version: string;

  /** Optional canonical URL for the exact upstream release/commit. */
  source_url?: string;

  /** Optional upstream git SHA (for git-pinnable sources). */
  source_commit?: string;

  /** ATR version at measurement time. Read from `package.json`. */
  atr_version: string;

  /** ATR git commit at measurement time (short SHA). */
  atr_commit: string;

  /** Total rule count in the engine at measurement time. */
  rules_loaded: number;

  /** ISO 8601 UTC timestamp. Example: `"2026-05-23T03:57:58.869Z"`. */
  measured_at: string;

  /** Total sample count in the evaluated corpus. */
  samples: number;

  /** Core metrics. All four required. */
  metrics: Metrics;

  /** Confusion matrix. Optional; strongly recommended. */
  confusion?: Confusion;

  /** Engine latency profile. Optional. */
  latency_ms?: LatencyMs;

  /** Source-defined per-category / per-family / per-severity breakdown. Optional. */
  breakdown?: Breakdown;

  /** Free-text context. Optional. Keep brief. */
  notes?: string;
}

/**
 * `latest.json` per source. Points to the most recent measurement file.
 *
 * The pointer is a relative path from the `<source>/` directory.
 * Consumers should NOT cache; the file is small and re-reading is cheap.
 */
export interface LatestPointer {
  source: string;
  /** Filename of the latest measurement, relative to the `<source>/` directory. */
  file: string;
  /** Mirror of the measurement's `measured_at`, for fast inspection. */
  measured_at: string;
  /** Mirror of `metrics` for fast aggregation without reading the underlying file. */
  metrics: Metrics;
  /** Mirror of `source_version` and `atr_version` for fast inspection. */
  source_version: string;
  atr_version: string;
  /** Mirror of `samples`. */
  samples: number;
}

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Error thrown when a measurement file fails schema validation.
 * Includes the field path and reason for fast debugging.
 */
export class MeasurementSchemaError extends Error {
  constructor(
    public readonly path: string,
    public readonly reason: string,
  ) {
    super(`measurement schema: ${path}: ${reason}`);
    this.name = "MeasurementSchemaError";
  }
}

function assertString(v: unknown, path: string, opts?: { nonEmpty?: boolean }): string {
  if (typeof v !== "string") {
    throw new MeasurementSchemaError(path, `expected string, got ${typeof v}`);
  }
  if (opts?.nonEmpty && v.length === 0) {
    throw new MeasurementSchemaError(path, "expected non-empty string");
  }
  return v;
}

function assertNumber(v: unknown, path: string, opts?: { min?: number; max?: number; integer?: boolean }): number {
  if (typeof v !== "number" || Number.isNaN(v) || !Number.isFinite(v)) {
    throw new MeasurementSchemaError(path, `expected finite number, got ${JSON.stringify(v)}`);
  }
  if (opts?.integer && !Number.isInteger(v)) {
    throw new MeasurementSchemaError(path, `expected integer, got ${v}`);
  }
  if (opts?.min !== undefined && v < opts.min) {
    throw new MeasurementSchemaError(path, `expected >= ${opts.min}, got ${v}`);
  }
  if (opts?.max !== undefined && v > opts.max) {
    throw new MeasurementSchemaError(path, `expected <= ${opts.max}, got ${v}`);
  }
  return v;
}

function assertObject(v: unknown, path: string): Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new MeasurementSchemaError(path, `expected object, got ${Array.isArray(v) ? "array" : typeof v}`);
  }
  return v as Record<string, unknown>;
}

function parseMetrics(raw: unknown, path: string): Metrics {
  const obj = assertObject(raw, path);
  return {
    recall: assertNumber(obj.recall, `${path}.recall`, { min: 0, max: 1 }),
    precision: assertNumber(obj.precision, `${path}.precision`, { min: 0, max: 1 }),
    f1: assertNumber(obj.f1, `${path}.f1`, { min: 0, max: 1 }),
    fp_rate: assertNumber(obj.fp_rate, `${path}.fp_rate`, { min: 0, max: 1 }),
  };
}

function parseConfusion(raw: unknown, path: string): Confusion {
  const obj = assertObject(raw, path);
  return {
    tp: assertNumber(obj.tp, `${path}.tp`, { min: 0, integer: true }),
    fp: assertNumber(obj.fp, `${path}.fp`, { min: 0, integer: true }),
    tn: assertNumber(obj.tn, `${path}.tn`, { min: 0, integer: true }),
    fn: assertNumber(obj.fn, `${path}.fn`, { min: 0, integer: true }),
  };
}

function parseLatency(raw: unknown, path: string): LatencyMs {
  const obj = assertObject(raw, path);
  return {
    p50: assertNumber(obj.p50, `${path}.p50`, { min: 0 }),
    p95: assertNumber(obj.p95, `${path}.p95`, { min: 0 }),
    p99: assertNumber(obj.p99, `${path}.p99`, { min: 0 }),
    mean: assertNumber(obj.mean, `${path}.mean`, { min: 0 }),
    max: assertNumber(obj.max, `${path}.max`, { min: 0 }),
  };
}

const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const SOURCE_RE = /^[a-z0-9][a-z0-9-]*$/;

/**
 * Parse a `Measurement` from an arbitrary value. Throws `MeasurementSchemaError`
 * on any deviation from the schema. Returns a strongly-typed `Measurement`.
 *
 * Unknown extra top-level keys are allowed but ignored (forward-compat); they
 * are NOT preserved in the returned object.
 */
export function parseMeasurement(raw: unknown): Measurement {
  const obj = assertObject(raw, "$");
  const schema_version = assertString(obj.schema_version, "$.schema_version", { nonEmpty: true });
  if (schema_version !== CURRENT_SCHEMA_VERSION) {
    throw new MeasurementSchemaError(
      "$.schema_version",
      `expected "${CURRENT_SCHEMA_VERSION}", got "${schema_version}" — older formats need migration`,
    );
  }
  const source = assertString(obj.source, "$.source", { nonEmpty: true });
  if (!SOURCE_RE.test(source)) {
    throw new MeasurementSchemaError(
      "$.source",
      `must match /^[a-z0-9][a-z0-9-]*$/; got "${source}"`,
    );
  }
  const measured_at = assertString(obj.measured_at, "$.measured_at", { nonEmpty: true });
  if (!ISO8601_RE.test(measured_at)) {
    throw new MeasurementSchemaError(
      "$.measured_at",
      `must be ISO 8601 UTC (e.g. "2026-05-23T03:57:58Z"); got "${measured_at}"`,
    );
  }
  const m: Measurement = {
    schema_version: CURRENT_SCHEMA_VERSION,
    source,
    source_version: assertString(obj.source_version, "$.source_version", { nonEmpty: true }),
    atr_version: assertString(obj.atr_version, "$.atr_version", { nonEmpty: true }),
    atr_commit: assertString(obj.atr_commit, "$.atr_commit", { nonEmpty: true }),
    rules_loaded: assertNumber(obj.rules_loaded, "$.rules_loaded", { min: 1, integer: true }),
    measured_at,
    samples: assertNumber(obj.samples, "$.samples", { min: 0, integer: true }),
    metrics: parseMetrics(obj.metrics, "$.metrics"),
  };
  if (obj.source_url !== undefined) m.source_url = assertString(obj.source_url, "$.source_url", { nonEmpty: true });
  if (obj.source_commit !== undefined) m.source_commit = assertString(obj.source_commit, "$.source_commit", { nonEmpty: true });
  if (obj.confusion !== undefined) m.confusion = parseConfusion(obj.confusion, "$.confusion");
  if (obj.latency_ms !== undefined) m.latency_ms = parseLatency(obj.latency_ms, "$.latency_ms");
  if (obj.breakdown !== undefined) m.breakdown = assertObject(obj.breakdown, "$.breakdown");
  if (obj.notes !== undefined) m.notes = assertString(obj.notes, "$.notes");
  return m;
}

/** Parse a `LatestPointer`. Throws on schema violation. */
export function parseLatestPointer(raw: unknown): LatestPointer {
  const obj = assertObject(raw, "$");
  return {
    source: assertString(obj.source, "$.source", { nonEmpty: true }),
    file: assertString(obj.file, "$.file", { nonEmpty: true }),
    measured_at: assertString(obj.measured_at, "$.measured_at", { nonEmpty: true }),
    metrics: parseMetrics(obj.metrics, "$.metrics"),
    source_version: assertString(obj.source_version, "$.source_version", { nonEmpty: true }),
    atr_version: assertString(obj.atr_version, "$.atr_version", { nonEmpty: true }),
    samples: assertNumber(obj.samples, "$.samples", { min: 0, integer: true }),
  };
}

/**
 * Compute the canonical filename for a measurement.
 *
 * Format: `<YYYY-MM-DD>_<source>-<source_version>_atr-<atr_version>.json`
 *
 * `source_version` and `atr_version` are slugified (lowercase, non-alphanumeric
 * → `-`, leading/trailing `-` removed, collapsed runs of `-`).
 */
export function measurementFilename(m: Pick<Measurement, "measured_at" | "source" | "source_version" | "atr_version">): string {
  const date = m.measured_at.slice(0, 10);
  const sourceSlug = slugify(m.source);
  const sourceVerSlug = slugify(m.source_version);
  const atrVerSlug = slugify(m.atr_version);
  return `${date}_${sourceSlug}-${sourceVerSlug}_atr-${atrVerSlug}.json`;
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}
