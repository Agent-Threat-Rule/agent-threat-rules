#!/usr/bin/env node
/**
 * corpus-owner-report.ts — who actually owns the benign corpus.
 *
 * The corpus decides which rules may enter the enforce lane: a rule that matches
 * anything in it is held back. So whoever contributed the most samples has the
 * most say over what ATR is allowed to auto-block, and nobody has been counting.
 *
 * REPORT ONLY. This enforces nothing and changes no file. A concentration cap is
 * worth having, but picking the threshold before seeing the distribution would
 * cut real ecosystem samples on a guess.
 *
 * Usage:
 *   npx tsx scripts/corpus-owner-report.ts            # table to stdout
 *   npx tsx scripts/corpus-owner-report.ts --json     # machine-readable
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The corpora that gate promotions, i.e. the ones with power over the enforce lane. */
const CORPORA = [
  "data/skill-benchmark/benign",
  "data/benign-corpus-extended",
  "data/benign-code",
] as const;

interface Sample {
  readonly source: string;
  readonly owner: string;
}

/**
 * Best-effort owner for a sample. Sources carry different identifier shapes, so
 * an unattributable sample is reported as such rather than bucketed into a
 * plausible-looking owner -- an invented attribution would be worse than a gap.
 */
function ownerOf(record: Record<string, unknown>): string {
  const candidates = ["source_id", "repo", "url", "id", "name", "package"];
  for (const key of candidates) {
    const raw = record[key];
    if (typeof raw !== "string" || raw.length === 0) continue;

    // A URL from somewhere other than a code host attributes to that host, not
    // to a person: arxiv abstracts are all one publisher and should read that
    // way rather than collapsing into a "http:" bucket.
    const url = /^https?:\/\//.exec(raw) ? tryUrl(raw) : null;
    if (url !== null) {
      const host = url.hostname.replace(/^www\./, "");
      if (host === "github.com") {
        const [head] = url.pathname.replace(/^\//, "").split("/");
        if (head !== undefined && head.length > 0) return head;
      }
      return host;
    }

    const [head] = raw.replace(/^@/, "").split("/");
    if (head !== undefined && head.length > 0 && !head.includes(" ")) return head;
  }
  return "(unattributed)";
}

function tryUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function loadSamples(): Sample[] {
  const out: Sample[] = [];
  for (const rel of CORPORA) {
    const base = join(REPO_ROOT, rel);
    if (!existsSync(base)) continue;
    const files = statSync(base).isDirectory()
      ? readdirSync(base).map((e) => join(base, e))
      : [base];
    for (const file of files) {
      if (!statSync(file).isFile()) continue;
      const source = file.replace(`${REPO_ROOT}/`, "");
      if (file.endsWith(".md")) {
        // One manifest per file; the directory is the attribution we have.
        out.push({ owner: "(skill-benchmark fixtures)", source });
        continue;
      }
      if (!file.endsWith(".jsonl")) continue;
      for (const line of readFileSync(file, "utf-8").split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          out.push({ owner: ownerOf(JSON.parse(trimmed) as Record<string, unknown>), source });
        } catch {
          out.push({ owner: "(unparseable)", source });
        }
      }
    }
  }
  return out;
}

function tally(samples: readonly Sample[], key: (s: Sample) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const s of samples) counts.set(key(s), (counts.get(key(s)) ?? 0) + 1);
  return new Map([...counts].sort((a, b) => b[1] - a[1]));
}

function main(): void {
  const samples = loadSamples();
  const total = samples.length;
  if (total === 0) {
    console.error("[owner-report] no corpus samples found; is the repo root right?");
    process.exit(1);
  }

  const byOwner = tally(samples, (s) => s.owner);
  const bySource = tally(samples, (s) => s.source);

  if (process.argv.includes("--json")) {
    console.log(
      JSON.stringify(
        {
          total,
          owners: [...byOwner].map(([owner, n]) => ({ owner, n, pct: +(n * 100 / total).toFixed(2) })),
          sources: [...bySource].map(([source, n]) => ({ source, n })),
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(`benign corpus that gates the enforce lane: ${total} samples\n`);
  console.log("by source file");
  for (const [source, n] of bySource) {
    console.log(`  ${String(n).padStart(6)}  ${((n * 100) / total).toFixed(1).padStart(5)}%  ${source}`);
  }
  console.log("\nby owner (top 15)");
  for (const [owner, n] of [...byOwner].slice(0, 15)) {
    console.log(`  ${String(n).padStart(6)}  ${((n * 100) / total).toFixed(1).padStart(5)}%  ${owner}`);
  }

  const [top] = [...byOwner];
  if (top !== undefined) {
    const [owner, n] = top;
    const pct = (n * 100) / total;
    console.log(
      `\nlargest single owner: ${owner} at ${pct.toFixed(1)}% of everything that can ` +
        `hold a rule out of the enforce lane.`,
    );
  }
  console.log("\nReport only; nothing was enforced or changed.");
}

main();
