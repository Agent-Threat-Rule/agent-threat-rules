#!/usr/bin/env npx tsx
/**
 * scripts/sync-stats-from-measurements.ts
 *
 * Reads every `data/measurements/<source>/latest.json`, projects them into the
 * `benchmarks` field of `data/stats.json`, and writes `stats.json` atomically.
 *
 * Exit codes:
 *   0  stats.json on disk matched what we would write OR was updated successfully.
 *   1  --check mode: stats.json on disk is stale relative to current measurements.
 *
 * Usage:
 *   npx tsx scripts/sync-stats-from-measurements.ts            # update stats.json
 *   npx tsx scripts/sync-stats-from-measurements.ts --check    # CI: exit 1 if stale
 *   npx tsx scripts/sync-stats-from-measurements.ts --dry-run  # show diff, don't write
 *
 * Design notes:
 *   - We DO NOT touch any field of stats.json other than `benchmarks` and
 *     `generated_at`. The existing schema (rules.total, ecosystem.*, etc.) is
 *     preserved verbatim. This keeps backwards compat with the auto-crystallize
 *     bot that also writes to stats.json.
 *   - We write atomically (tmp + fsync + rename). Concurrent updates from other
 *     workflows are safe (last writer wins on rename, no half-written file).
 *   - `--check` mode is intended for CI. It computes the projection and
 *     compares it against `stats.json.benchmarks`; if they diverge, exits 1.
 */

import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { aggregateMeasurements, projectForStats } from "./measurement/aggregate.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const STATS_PATH = resolve(REPO_ROOT, "data", "stats.json");

const CHECK = process.argv.includes("--check");
const DRY_RUN = process.argv.includes("--dry-run");

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

function main(): number {
  const agg = aggregateMeasurements();
  const projection = projectForStats(agg);

  if (agg.sources_broken.length > 0) {
    console.error(`WARNING: ${agg.sources_broken.length} source(s) have broken latest.json:`);
    for (const b of agg.sources_broken) {
      console.error(`  ${b.source} → ${b.reason}`);
    }
  }

  // Read existing stats.json if any; preserve unrelated top-level keys.
  let existing: Record<string, unknown> = {};
  if (existsSync(STATS_PATH)) {
    try {
      existing = JSON.parse(readFileSync(STATS_PATH, "utf-8")) as Record<string, unknown>;
    } catch (err) {
      console.error(`failed to parse existing stats.json: ${err instanceof Error ? err.message : String(err)}`);
      return 1;
    }
  }

  const next: Record<string, unknown> = {
    ...existing,
    benchmarks: projection.benchmarks,
    benchmarks_generated_at: projection.generated_at,
  };

  const nextJson = JSON.stringify(next, null, 2) + "\n";
  const existingJson = existsSync(STATS_PATH) ? readFileSync(STATS_PATH, "utf-8") : "";

  // Normalise both sides by reparsing+restringifying the benchmarks slice so
  // we don't false-fail on whitespace or generated_at drift in --check mode.
  if (CHECK) {
    const existingBenchmarks = JSON.stringify(
      (existing as { benchmarks?: unknown }).benchmarks ?? null,
    );
    const nextBenchmarks = JSON.stringify(projection.benchmarks);
    if (existingBenchmarks === nextBenchmarks) {
      console.error("stats.json benchmarks: up-to-date");
      return 0;
    }
    console.error("stats.json benchmarks: STALE — re-run without --check to update");
    console.error("  expected:", nextBenchmarks.slice(0, 200) + (nextBenchmarks.length > 200 ? "…" : ""));
    console.error("  on-disk: ", existingBenchmarks.slice(0, 200) + (existingBenchmarks.length > 200 ? "…" : ""));
    return 1;
  }

  if (DRY_RUN) {
    if (existingJson === nextJson) {
      console.error("stats.json unchanged");
    } else {
      console.error("stats.json would be updated:");
      console.error(JSON.stringify(projection, null, 2));
    }
    return 0;
  }

  if (existingJson === nextJson) {
    console.error("stats.json already current — no write needed");
    return 0;
  }

  writeFileAtomic(STATS_PATH, nextJson);
  console.error(
    `stats.json updated: ${projection.benchmarks.length} benchmark entr${projection.benchmarks.length === 1 ? "y" : "ies"}` +
      (agg.sources_pending.length ? ` (${agg.sources_pending.length} source(s) pending first measurement)` : ""),
  );
  return 0;
}

process.exit(main());
