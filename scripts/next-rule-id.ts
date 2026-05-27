#!/usr/bin/env node
/**
 * next-rule-id.ts — Allocate the next free ATR rule ID(s).
 *
 * Why: contributors picking IDs by inspection keep colliding with each other
 * (PR #56 → #71 and PR #57 both renumbered post-hoc because 00525-00530 were
 * already claimed). The CI safety gate in validate.yml catches collisions
 * before merge, but it costs a force-push + reviewer round-trip. This helper
 * surfaces the next free ID(s) upfront so the first try lands.
 *
 * Usage:
 *   npx tsx scripts/next-rule-id.ts            # next 1 ID
 *   npx tsx scripts/next-rule-id.ts 5          # next 5 IDs
 *   npx tsx scripts/next-rule-id.ts --include-open-prs   # also scan open PRs (gh required)
 *   npx tsx scripts/next-rule-id.ts --year 2026          # default = current year
 *   npx tsx scripts/next-rule-id.ts --json     # machine-readable output
 *
 * Exit codes:
 *   0 — printed the requested IDs
 *   1 — usage error
 *   2 — could not enumerate (rules dir missing, etc.)
 */

import { execFileSync } from "node:child_process";
import { readdirSync, existsSync, statSync, readFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const ID_REGEX = /ATR-(\d{4})-(\d{5,})/g;

interface Args {
  readonly count: number;
  readonly year: number;
  readonly includeOpenPrs: boolean;
  readonly jsonOutput: boolean;
}

function parseArgs(argv: readonly string[]): Args {
  let count = 1;
  let year = new Date().getUTCFullYear();
  let includeOpenPrs = false;
  let jsonOutput = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--include-open-prs") {
      includeOpenPrs = true;
    } else if (arg === "--json") {
      jsonOutput = true;
    } else if (arg === "--year") {
      const next = argv[i + 1];
      if (!next) {
        console.error("--year requires a value");
        process.exit(1);
      }
      const parsed = Number.parseInt(next, 10);
      if (!Number.isFinite(parsed) || parsed < 2000 || parsed > 2100) {
        console.error(`--year must be a 4-digit year, got ${next}`);
        process.exit(1);
      }
      year = parsed;
      i++;
    } else if (arg === "-h" || arg === "--help") {
      console.log(
        `Usage: next-rule-id.ts [count] [--year YYYY] [--include-open-prs] [--json]\n` +
          `  count                Number of IDs to allocate (default 1).\n` +
          `  --year YYYY          Year prefix to allocate under (default current).\n` +
          `  --include-open-prs   Also scan open PRs via gh CLI for in-flight IDs.\n` +
          `  --json               Output {"ids": [...]} instead of one ID per line.`,
      );
      process.exit(0);
    } else if (/^\d+$/.test(arg)) {
      const parsed = Number.parseInt(arg, 10);
      if (parsed < 1 || parsed > 1000) {
        console.error(`count must be 1..1000, got ${parsed}`);
        process.exit(1);
      }
      count = parsed;
    } else {
      console.error(`Unknown argument: ${arg}`);
      process.exit(1);
    }
  }

  return { count, year, includeOpenPrs, jsonOutput };
}

/** Recursively walk a directory for .yaml/.yml files. */
function walkYamlFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    let st;
    try {
      st = statSync(path);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      out.push(...walkYamlFiles(path));
    } else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) {
      out.push(path);
    }
  }
  return out;
}

/** Extract every ATR-YYYY-NNNNN id seen in a string. */
function extractIds(text: string): Array<{ year: number; seq: number }> {
  const out: Array<{ year: number; seq: number }> = [];
  for (const match of text.matchAll(ID_REGEX)) {
    const y = Number.parseInt(match[1] ?? "0", 10);
    const n = Number.parseInt(match[2] ?? "0", 10);
    if (Number.isFinite(y) && Number.isFinite(n)) out.push({ year: y, seq: n });
  }
  return out;
}

/**
 * Read every rule file under rules/ and collect the ATR IDs present.
 * Looks at filename AND file body to catch IDs that may not match the filename.
 */
function collectIdsFromRulesDir(): Set<string> {
  const used = new Set<string>();
  for (const file of walkYamlFiles(RULES_DIR)) {
    // Filename ID
    for (const id of extractIds(file)) {
      used.add(`${id.year}-${id.seq}`);
    }
    // Body ID (id: ATR-2026-...)
    try {
      const text = readFileSync(file, "utf-8");
      for (const id of extractIds(text)) {
        used.add(`${id.year}-${id.seq}`);
      }
    } catch {
      /* skip unreadable file */
    }
  }
  return used;
}

/**
 * Best-effort: use the gh CLI to enumerate open PRs and collect ATR IDs
 * mentioned in their titles, bodies, or rule file additions. Returns an empty
 * set if gh is unavailable.
 */
function collectIdsFromOpenPrs(): Set<string> {
  const used = new Set<string>();
  let prs: Array<{ number: number; title: string; body: string; files: Array<{ path: string }> }>;
  try {
    const out = execFileSync(
      "gh",
      [
        "pr",
        "list",
        "--state",
        "open",
        "--limit",
        "100",
        "--json",
        "number,title,body,files",
      ],
      { cwd: REPO_ROOT, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] },
    );
    prs = JSON.parse(out);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `[next-rule-id] skipping open-PR scan (gh CLI not available or not authenticated): ${msg}\n`,
    );
    return used;
  }
  for (const pr of prs) {
    const haystack =
      `${pr.title}\n${pr.body ?? ""}\n${(pr.files ?? []).map((f) => f.path).join("\n")}`;
    for (const id of extractIds(haystack)) {
      used.add(`${id.year}-${id.seq}`);
    }
  }
  return used;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  if (!existsSync(RULES_DIR)) {
    console.error(`rules/ directory not found at ${RULES_DIR}`);
    process.exit(2);
  }

  const used = collectIdsFromRulesDir();
  if (args.includeOpenPrs) {
    for (const id of collectIdsFromOpenPrs()) used.add(id);
  }

  // Find the highest in-use sequence for the requested year.
  let maxSeq = 0;
  for (const key of used) {
    const [y, s] = key.split("-").map((x) => Number.parseInt(x, 10));
    if (y === args.year && Number.isFinite(s) && s > maxSeq) maxSeq = s;
  }

  // Allocate the next `count` sequential IDs.
  const allocated: string[] = [];
  for (let i = 1; i <= args.count; i++) {
    const seq = (maxSeq + i).toString().padStart(5, "0");
    allocated.push(`ATR-${args.year}-${seq}`);
  }

  if (args.jsonOutput) {
    process.stdout.write(JSON.stringify({ ids: allocated }) + "\n");
  } else {
    for (const id of allocated) process.stdout.write(id + "\n");
  }
}

main();
