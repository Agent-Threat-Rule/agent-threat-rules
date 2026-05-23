/**
 * scripts/measurement/write.ts
 *
 * Atomic writer + helpers for ATR benchmark measurement files.
 *
 * Used by every eval script. Guarantees:
 *   - Schema-valid output (calls `parseMeasurement` before write).
 *   - Atomic write (tmp file + fsync + rename — no half-written files).
 *   - `latest.json` is updated only after the underlying file is durable on disk.
 *   - Caller-supplied measurements receive `schema_version`, `measured_at`,
 *     `atr_version`, `atr_commit`, and `rules_loaded` autofills if omitted.
 */

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

import {
  CURRENT_SCHEMA_VERSION,
  type LatestPointer,
  type Measurement,
  measurementFilename,
  parseLatestPointer,
  parseMeasurement,
} from "./schema.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");
const MEASUREMENTS_DIR = resolve(REPO_ROOT, "data", "measurements");

// ─── Environment auto-detection ─────────────────────────────────────────────

/** Read the ATR version from `package.json`. */
export function readATRVersion(): string {
  const pkg = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8")) as { version?: unknown };
  if (typeof pkg.version !== "string" || pkg.version.length === 0) {
    throw new Error("package.json: missing or non-string `version`");
  }
  return pkg.version;
}

/** Read the current short git SHA. Falls back to `"unknown"` outside a git repo. */
export function readATRCommit(): string {
  try {
    return execFileSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "ignore"],
    }).toString().trim();
  } catch {
    return "unknown";
  }
}

/** Best-effort: count `ATR-*.yaml` rule files under `rules/`. */
export function countRules(rulesDir = resolve(REPO_ROOT, "rules")): number {
  const out = execFileSync("find", [rulesDir, "-name", "ATR-*.yaml"], {
    stdio: ["ignore", "pipe", "ignore"],
  }).toString();
  return out.split("\n").filter((l) => l.trim().length > 0).length;
}

// ─── Atomic write primitives ────────────────────────────────────────────────

/**
 * Write `content` to `targetPath` atomically.
 *
 * Implementation: write to `<targetPath>.<pid>.<nonce>.tmp`, `fsync()` the file
 * descriptor, then `rename()` over the target. POSIX `rename(2)` is atomic; if
 * the process dies between write and rename, the target is untouched and the
 * tmp file can be cleaned up safely.
 *
 * If `fs.renameSync` fails (cross-device EXDEV, permissions), throws.
 */
function writeFileAtomic(targetPath: string, content: string): void {
  mkdirSync(dirname(targetPath), { recursive: true });
  const nonce = Math.random().toString(36).slice(2, 10);
  const tmpPath = `${targetPath}.${process.pid}.${nonce}.tmp`;
  const fd = openSync(tmpPath, "w");
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmpPath, targetPath);
}

// ─── Latest pointer ─────────────────────────────────────────────────────────

function deriveLatestPointer(m: Measurement, filename: string): LatestPointer {
  return {
    source: m.source,
    file: filename,
    measured_at: m.measured_at,
    metrics: m.metrics,
    source_version: m.source_version,
    atr_version: m.atr_version,
    samples: m.samples,
  };
}

/**
 * Decide whether `candidate` is more recent than the existing `latest.json`.
 * Pure function (no I/O); given two pointer-shaped objects, returns boolean.
 */
function isStrictlyNewer(candidate: { measured_at: string }, existing: { measured_at: string }): boolean {
  return candidate.measured_at > existing.measured_at;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Caller-friendly subset of `Measurement`. The fields the eval script must
 * provide; the rest (`schema_version`, `atr_version`, `atr_commit`,
 * `rules_loaded`, `measured_at`) are autofilled by `writeMeasurement()`.
 *
 * Callers MAY override any autofill by setting the field explicitly.
 */
export type MeasurementInput = Omit<
  Measurement,
  "schema_version" | "measured_at" | "atr_version" | "atr_commit" | "rules_loaded"
> & {
  measured_at?: string;
  atr_version?: string;
  atr_commit?: string;
  rules_loaded?: number;
};

/**
 * Write a measurement file and update the source's `latest.json`.
 *
 * Returns the absolute path of the measurement file that was written.
 *
 * Behavior:
 *   1. Autofill `schema_version`, `measured_at` (now, ISO UTC), `atr_version`,
 *      `atr_commit`, `rules_loaded` if not provided.
 *   2. Validate via `parseMeasurement()`. Throws on any schema violation.
 *   3. Compute the canonical filename.
 *   4. Refuse to overwrite an existing file unless `opts.force` is true. (We
 *      maintain the append-only invariant by default.)
 *   5. Atomic write the measurement file.
 *   6. Update `latest.json` only if the new measurement is strictly newer.
 *
 * @param input  Measurement minus the autofilled fields.
 * @param opts   Options. `force: true` allows overwriting an existing file
 *               with the same filename (use with caution; breaks append-only).
 */
export function writeMeasurement(
  input: MeasurementInput,
  opts: { force?: boolean; rulesDir?: string } = {},
): { measurementPath: string; latestPath: string; measurement: Measurement } {
  const measured_at = input.measured_at ?? new Date().toISOString();
  const atr_version = input.atr_version ?? readATRVersion();
  const atr_commit = input.atr_commit ?? readATRCommit();
  const rules_loaded = input.rules_loaded ?? countRules(opts.rulesDir);

  const measurement: Measurement = parseMeasurement({
    schema_version: CURRENT_SCHEMA_VERSION,
    ...input,
    measured_at,
    atr_version,
    atr_commit,
    rules_loaded,
  });

  const sourceDir = join(MEASUREMENTS_DIR, measurement.source);
  const filename = measurementFilename(measurement);
  const measurementPath = join(sourceDir, filename);
  const latestPath = join(sourceDir, "latest.json");

  if (existsSync(measurementPath) && !opts.force) {
    throw new Error(
      `measurement already exists: ${measurementPath}\n` +
        `Re-running the same (source, source_version, atr_version) on the same day produces the same filename.\n` +
        `Pass { force: true } to overwrite, or change one of the inputs.`,
    );
  }

  const measurementJson = JSON.stringify(measurement, null, 2) + "\n";
  writeFileAtomic(measurementPath, measurementJson);

  // Update latest.json only if strictly newer than the existing pointer.
  const newPointer = deriveLatestPointer(measurement, filename);
  let shouldWriteLatest = true;
  if (existsSync(latestPath)) {
    try {
      const existing = parseLatestPointer(JSON.parse(readFileSync(latestPath, "utf-8")));
      shouldWriteLatest = isStrictlyNewer(newPointer, existing);
    } catch {
      // Corrupt or missing latest.json — overwrite it.
      shouldWriteLatest = true;
    }
  }
  if (shouldWriteLatest) {
    writeFileAtomic(latestPath, JSON.stringify(newPointer, null, 2) + "\n");
  }

  return { measurementPath, latestPath, measurement };
}

/** Resolve the absolute path of a source's `latest.json`. */
export function latestPath(source: string): string {
  return join(MEASUREMENTS_DIR, source, "latest.json");
}

/** Absolute path of the measurements root directory. */
export function measurementsDir(): string {
  return MEASUREMENTS_DIR;
}
