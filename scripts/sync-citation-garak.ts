#!/usr/bin/env npx tsx
/**
 * scripts/sync-citation-garak.ts
 *
 * Rewrite (or, with --check, verify) the garak sentence in CITATION.cff from
 * root stats.json's `benchmarks.garak` block. sync-stats.ts does the same
 * whenever rules/ changes on main (reconcile-stats.yml); this runs it on its
 * own, so the weekly measurement run carries a new garak figure into
 * CITATION.cff in the same PR that moves stats.json, and CI fails when the two
 * disagree.
 *
 * Usage:
 *   npx tsx scripts/sync-citation-garak.ts                       # rewrite in place
 *   npx tsx scripts/sync-citation-garak.ts --check               # exit 1 if stale or unrenderable
 *   npx tsx scripts/sync-citation-garak.ts --root <dir>          # another checkout (tests, CI)
 *   npx tsx scripts/sync-citation-garak.ts --review-notes <file> # append a failure to the rolling PR body
 *
 * Exit codes: 0 = current (or rewritten). 1 = --check found it stale, or the
 * sentence or the garak block is missing or malformed. In write mode such a
 * failure is a warning (and a --review-notes entry) instead: the weekly run
 * must still push its measurements, and the PR's --check then fails.
 */

import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { appendReviewNotes } from "./lib/append-review-notes.js";
import { type GarakCitation, syncGarakSentence } from "./lib/citation-garak.js";

const DEFAULT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function flagValue(argv: readonly string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} needs a value`);
  return value;
}

/** CITATION.cff as it is, and as root stats.json says it should be. Throws when it cannot be rendered. */
function render(root: string): { path: string; before: string; after: string } {
  const stats = JSON.parse(readFileSync(resolve(root, "stats.json"), "utf-8")) as {
    version?: string;
    benchmarks?: { garak?: GarakCitation };
  };
  const garak = stats.benchmarks?.garak;
  if (garak === undefined) throw new Error("stats.json has no benchmarks.garak block");
  const path = resolve(root, "CITATION.cff");
  const before = readFileSync(path, "utf-8");
  return { path, before, after: syncGarakSentence(before, garak, stats.version ?? "unknown") };
}

function main(argv: readonly string[]): number {
  const check = argv.includes("--check");
  let notes: string | undefined;
  try {
    notes = flagValue(argv, "--review-notes");
    const { path, before, after } = render(resolve(flagValue(argv, "--root") ?? DEFAULT_ROOT));
    if (check) {
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
    const message = err instanceof Error ? err.message : String(err);
    if (check) {
      console.error(`FAIL: ${message}`);
      return 1;
    }
    console.error(`::warning::CITATION.cff garak sentence not rendered: ${message}`);
    if (notes !== undefined) {
      appendReviewNotes(notes, "CITATION.cff not re-rendered", "scripts/sync-citation-garak.ts could not render the garak sentence; CI's --check fails until this is fixed:", [message]);
    }
    return 0;
  }
}

// Real paths on both sides: a script run through a symlink (or macOS's /tmp)
// sees its own URL resolved while argv keeps the path it was called by.
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
