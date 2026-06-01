#!/usr/bin/env npx tsx
/**
 * check-collector-freshness.ts
 *
 * Guards against a CVE collector source silently going stale — an API change,
 * an expired credential, or a query that quietly starts returning nothing. The
 * daily workflow can keep reporting "success" while a source has stopped
 * pulling the latest CVEs, so this script makes that loud.
 *
 * For each source it checks:
 *   - the last collector run's exit_code / rate_limited (from last-run.json)
 *   - the newest CVE/advisory date found across that source's proposals,
 *     against a per-source staleness threshold
 *
 * Output: a human-readable report. Exit 1 if any source is stale or errored,
 * else 0. The workflow runs it with continue-on-error and surfaces the report
 * (step summary + issue) without blocking the rest of collection.
 *
 * Usage:
 *   npx tsx scripts/check-collector-freshness.ts
 *   npx tsx scripts/check-collector-freshness.ts --json
 *   ATR_FRESHNESS_TODAY=2026-06-02 npx tsx scripts/check-collector-freshness.ts  # pin "today" for tests
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROPOSALS = resolve(REPO_ROOT, "proposals");
const LAST_RUN = resolve(REPO_ROOT, "data/cve-collector/last-run.json");

// Per-source staleness threshold (days) + proposals subdir. Thresholds reflect
// how often each source realistically produces NEW agent CVEs: GHSA is very
// active, NVD lags, CISA-KEV adds AI entries sporadically.
const SOURCES: Record<string, { dir: string; maxAgeDays: number }> = {
  ghsa: { dir: "ghsa", maxAgeDays: 21 },
  nvd: { dir: "nvd", maxAgeDays: 30 },
  "cisa-kev": { dir: "cisa-kev", maxAgeDays: 120 },
  avid: { dir: "avid", maxAgeDays: 60 },
};

export interface SourceAssessment {
  source: string;
  newestDate: string | null;
  ageDays: number | null;
  maxAgeDays: number;
  exitCode: number | null;
  rateLimited: boolean;
  stale: boolean;
  errored: boolean;
  reasons: string[];
}

function today(): string {
  return process.env.ATR_FRESHNESS_TODAY || new Date().toISOString().slice(0, 10);
}

function daysBetween(a: string, b: string): number {
  return Math.round((Date.parse(b) - Date.parse(a)) / 86_400_000);
}

function walk(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    const s = statSync(f);
    if (s.isDirectory()) out.push(...walk(f));
    else if (f.endsWith(".yaml") || f.endsWith(".yml")) out.push(f);
  }
  return out;
}

function newestDateIn(dir: string): string | null {
  let newest: string | null = null;
  for (const f of walk(join(PROPOSALS, dir))) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    for (const d of raw.match(/\b20\d{2}[-/]\d{2}[-/]\d{2}\b/g) ?? []) {
      const norm = d.replace(/\//g, "-");
      if (norm <= today() && (!newest || norm > newest)) newest = norm;
    }
  }
  return newest;
}

/** Pure decision logic (no IO) — unit-testable. */
export function assessSource(input: {
  source: string;
  newestDate: string | null;
  maxAgeDays: number;
  exitCode: number | null;
  rateLimited: boolean;
  todayDate: string;
}): SourceAssessment {
  const { source, newestDate, maxAgeDays, exitCode, rateLimited, todayDate } = input;
  const ageDays = newestDate ? daysBetween(newestDate, todayDate) : null;
  const reasons: string[] = [];
  const errored = (exitCode !== null && exitCode !== 0) || rateLimited;
  if (rateLimited) reasons.push("rate-limited last run");
  if (exitCode !== null && exitCode !== 0) reasons.push(`collector exit_code=${exitCode}`);
  let stale = false;
  if (ageDays === null) {
    stale = true;
    reasons.push("no dated proposals found");
  } else if (ageDays > maxAgeDays) {
    stale = true;
    reasons.push(`newest CVE is ${ageDays}d old (> ${maxAgeDays}d threshold)`);
  }
  return { source, newestDate, ageDays, maxAgeDays, exitCode, rateLimited, stale, errored, reasons };
}

function main(): void {
  const asJson = process.argv.includes("--json");
  let lastRun: { sources?: Array<{ id: string; exit_code?: number; rate_limited?: boolean }> } = {};
  if (existsSync(LAST_RUN)) {
    try {
      lastRun = JSON.parse(readFileSync(LAST_RUN, "utf-8"));
    } catch {
      /* ignore */
    }
  }
  const byId = new Map((lastRun.sources ?? []).map((s) => [s.id, s]));
  const td = today();

  const results = Object.entries(SOURCES).map(([source, cfg]) => {
    const lr = byId.get(source);
    return assessSource({
      source,
      newestDate: newestDateIn(cfg.dir),
      maxAgeDays: cfg.maxAgeDays,
      exitCode: lr?.exit_code ?? null,
      rateLimited: lr?.rate_limited ?? false,
      todayDate: td,
    });
  });

  const bad = results.filter((r) => r.stale || r.errored);

  if (asJson) {
    console.log(JSON.stringify({ today: td, ok: bad.length === 0, results }, null, 2));
  } else {
    console.log(`Collector freshness (as of ${td}):`);
    for (const r of results) {
      const mark = r.stale || r.errored ? "STALE" : "ok   ";
      const age = r.ageDays === null ? "no dates" : `${r.ageDays}d old`;
      console.log(
        `  [${mark}] ${r.source.padEnd(9)} newest=${r.newestDate ?? "none"} (${age}, ≤${r.maxAgeDays}d)` +
          (r.reasons.length ? ` — ${r.reasons.join("; ")}` : ""),
      );
    }
    if (bad.length) {
      console.log(`\n${bad.length} source(s) need attention: ${bad.map((b) => b.source).join(", ")}`);
    } else {
      console.log("\nAll sources fresh.");
    }
  }
  process.exit(bad.length ? 1 : 0);
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) main();
