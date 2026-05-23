#!/usr/bin/env npx tsx
/**
 * scripts/measurement/verify.ts
 *
 * Walk `data/measurements/` and assert every JSON file conforms to the schema.
 * Exit 0 if all files pass; exit 1 with a listing of failures otherwise.
 *
 * Designed to run in CI on every PR. Fast (<1s for hundreds of files).
 *
 * Usage:
 *   npx tsx scripts/measurement/verify.ts
 *   npx tsx scripts/measurement/verify.ts --quiet     # only print on failure
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { MeasurementSchemaError, parseLatestPointer, parseMeasurement } from "../../src/measurement/schema.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");
const MEASUREMENTS_DIR = resolve(REPO_ROOT, "data", "measurements");

const QUIET = process.argv.includes("--quiet");

interface Failure {
  file: string;
  reason: string;
}

function isMeasurementFilename(name: string): boolean {
  // YYYY-MM-DD_*.json — excludes latest.json, README.md, etc.
  return /^\d{4}-\d{2}-\d{2}_.*\.json$/.test(name);
}

function verifyMeasurementFile(file: string): Failure | null {
  try {
    const raw = JSON.parse(readFileSync(file, "utf-8")) as unknown;
    parseMeasurement(raw);
    return null;
  } catch (err) {
    if (err instanceof MeasurementSchemaError) {
      return { file, reason: err.message };
    }
    if (err instanceof SyntaxError) {
      return { file, reason: `invalid JSON: ${err.message}` };
    }
    return { file, reason: err instanceof Error ? err.message : String(err) };
  }
}

function verifyLatestFile(file: string): Failure | null {
  try {
    const raw = JSON.parse(readFileSync(file, "utf-8")) as unknown;
    parseLatestPointer(raw);
    return null;
  } catch (err) {
    if (err instanceof MeasurementSchemaError) {
      return { file, reason: err.message };
    }
    return { file, reason: err instanceof Error ? err.message : String(err) };
  }
}

function main(): number {
  if (!existsSync(MEASUREMENTS_DIR)) {
    if (!QUIET) console.error(`measurements directory not found: ${MEASUREMENTS_DIR}`);
    return 0; // empty repo is valid
  }

  const failures: Failure[] = [];
  let measurementFilesChecked = 0;
  let latestFilesChecked = 0;
  let sourcesChecked = 0;

  for (const entry of readdirSync(MEASUREMENTS_DIR)) {
    const sourceDir = join(MEASUREMENTS_DIR, entry);
    if (!statSync(sourceDir).isDirectory()) continue;
    sourcesChecked++;
    for (const name of readdirSync(sourceDir)) {
      const path = join(sourceDir, name);
      if (name === "latest.json") {
        const f = verifyLatestFile(path);
        if (f) failures.push(f);
        latestFilesChecked++;
      } else if (isMeasurementFilename(name)) {
        const f = verifyMeasurementFile(path);
        if (f) failures.push(f);
        measurementFilesChecked++;
      }
      // README.md and other non-measurement files are ignored.
    }
  }

  if (failures.length > 0) {
    console.error(`measurement schema verification FAILED — ${failures.length} file(s) invalid:`);
    for (const f of failures) {
      console.error(`  ${f.file}`);
      console.error(`    → ${f.reason}`);
    }
    return 1;
  }

  if (!QUIET) {
    console.error(
      `measurement schema verification OK: ${sourcesChecked} source(s), ` +
        `${measurementFilesChecked} measurement file(s), ${latestFilesChecked} latest pointer(s)`,
    );
  }
  return 0;
}

process.exit(main());
