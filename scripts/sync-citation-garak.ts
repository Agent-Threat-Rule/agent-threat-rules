#!/usr/bin/env npx tsx
/**
 * scripts/sync-citation-garak.ts
 *
 * Rewrite (or, with --check, verify) the garak sentence in CITATION.cff from
 * root stats.json's `benchmarks.garak` block. sync-stats.ts does the same on
 * every rules-merge release; this runs it on its own, so the weekly measurement
 * run can carry a new garak figure into CITATION.cff in the same PR that moves
 * stats.json, and CI can fail when the two disagree.
 *
 * Usage:
 *   npx tsx scripts/sync-citation-garak.ts               # rewrite in place
 *   npx tsx scripts/sync-citation-garak.ts --check       # exit 1 if it would change
 *   npx tsx scripts/sync-citation-garak.ts --root <dir>  # another checkout (tests, CI)
 *
 * Exit codes: 0 = current (or rewritten). 1 = --check found it stale, or the
 * sentence or the garak block is missing.
 */

import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { type GarakCitation, syncGarakSentence } from "./lib/citation-garak.js";

const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function rootFrom(argv: readonly string[]): string {
  const i = argv.indexOf("--root");
  if (i === -1) return DEFAULT_ROOT;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error("--root needs a value");
  return resolve(value);
}

function main(argv: readonly string[]): number {
  try {
    const root = rootFrom(argv);
    const stats = JSON.parse(readFileSync(resolve(root, "stats.json"), "utf-8")) as {
      version?: string;
      benchmarks?: { garak?: GarakCitation };
    };
    const garak = stats.benchmarks?.garak;
    if (garak === undefined || typeof garak.recall !== "number" || typeof garak.samples !== "number") {
      throw new Error("stats.json has no benchmarks.garak block with a recall and samples");
    }
    const path = resolve(root, "CITATION.cff");
    const before = readFileSync(path, "utf-8");
    const after = syncGarakSentence(before, garak, stats.version ?? "unknown");
    if (argv.includes("--check")) {
      if (after === before) {
        console.log("CITATION.cff garak sentence matches stats.json.");
        return 0;
      }
      console.error("STALE: CITATION.cff's garak sentence differs from stats.json. Run `npx tsx scripts/sync-citation-garak.ts`.");
      return 1;
    }
    if (after !== before) writeFileSync(path, after);
    console.log(after === before ? "CITATION.cff garak sentence already current." : "rendered CITATION.cff");
    return 0;
  } catch (err) {
    console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
