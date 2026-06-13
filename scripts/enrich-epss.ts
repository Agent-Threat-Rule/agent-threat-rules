#!/usr/bin/env npx tsx
/**
 * enrich-epss.ts
 *
 * ENRICHMENT script -- NOT a proposal emitter. It annotates EXISTING
 * proposals/ yaml files with FIRST EPSS (Exploit Prediction Scoring System)
 * scores so the maintainer / promote step can prioritise which proposals to
 * crystallise into rules first.
 *
 * EPSS gives a 0..1 exploit-probability for a CVE (plus a percentile rank).
 * A high-EPSS agent CVE means there is real-world exploit pressure -- those
 * proposals should get a hand-authored detection.conditions before low-EPSS
 * ones. This is a PURE PRIORITISATION SIGNAL with zero overlap with any other
 * sync source (ghsa/huntr/nvd/...): it never touches detection.conditions or
 * any rule logic, only adds/updates an additive top-level `_epss:` block.
 *
 * Source:
 *   FIRST EPSS public API -- https://api.first.org/data/v1/epss
 *   Batch query: ?cve=CVE-2025-1,CVE-2025-2 (comma-separated, no auth,
 *   ~100 CVEs/request). Returns {data:[{cve, epss, percentile, date}, ...]}.
 *   epss and percentile come back as decimal STRINGS, parsed to float here.
 *
 * What it does:
 *   1. Walk proposals/ yaml, collect every references.cve value (dedup).
 *   2. Batch-query EPSS in chunks of EPSS_CHUNK CVEs.
 *   3. For each proposal that has a CVE with an EPSS score, add/update a
 *      top-level `_epss:` block:
 *          _epss:
 *            score: <float>
 *            percentile: <float>
 *            date: "<str>"
 *            cve: "<the scored CVE>"
 *            queried_at: "<iso>"
 *      Idempotent -- re-running replaces the existing block.
 *   4. Proposals without a CVE (arxiv / dblp / benchmark / owasp-asi etc.)
 *      are never touched. detection.conditions and all rule logic untouched.
 *
 * A proposal may list multiple CVEs; we annotate with the HIGHEST-EPSS CVE
 * among them (that is the prioritisation signal that matters), and record
 * which CVE it came from in `_epss.cve`.
 *
 * Flags:
 *   --write      apply the _epss block to disk (default: dry-run, writes
 *                nothing, reports counts + score distribution)
 *   --verbose    per-proposal logging
 *   --limit N    only process the first N CVE-bearing proposals
 *
 * Output:
 *   Human-readable JSON summary, then a marker line:
 *   ::epss-enrich-summary::{proposals_scanned, cves_unique, scores_found,
 *                           annotated, high_epss_count}
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network down for every chunk, unparseable API response)
 *   2 no data path (no CVE-bearing proposals found -- recoverable / no-op)
 *
 * Secret discipline: EPSS is a public, no-auth API. This script reads no
 * secrets and accepts no --key argument.
 */

import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const VERBOSE = flag("--verbose");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;

// FIRST asks for a descriptive UA. Public read, no auth.
const POLITE_UA =
  "ATR-EPSS-Enrich/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";
const EPSS_BASE = "https://api.first.org/data/v1/epss";
// FIRST documents ~100 CVEs/request; stay at 90 for URL-length safety.
const EPSS_CHUNK = 90;
// EPSS prioritisation threshold: probability > 0.5 == actively exploited-ish.
const HIGH_EPSS = 0.5;

const RATE_LIMIT_MS = 1000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const CVE_RE = /^CVE-\d{4}-\d{3,}$/i;

// ---------------------------------------------------------------------------
// Walk proposals/ yaml (same pattern as sync-huntr.ts walkYaml).
// ---------------------------------------------------------------------------

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

// Pull references.cve out of one parsed proposal doc. Tolerates string or
// array, normalises case to upper, and only keeps well-formed CVE ids.
function cvesFromDoc(doc: unknown): string[] {
  const refs = (doc as { references?: { cve?: unknown } })?.references;
  if (!refs || typeof refs !== "object") return [];
  const raw = (refs as { cve?: unknown }).cve;
  const list: string[] = [];
  if (typeof raw === "string") list.push(raw);
  else if (Array.isArray(raw))
    for (const c of raw) if (typeof c === "string") list.push(c);
  const out: string[] = [];
  for (const c of list) {
    const v = c.trim().toUpperCase();
    if (CVE_RE.test(v) && !out.includes(v)) out.push(v);
  }
  return out;
}

// ---------------------------------------------------------------------------
// EPSS batch query.
// ---------------------------------------------------------------------------

interface EpssScore {
  cve: string;
  epss: number;
  percentile: number;
  date: string;
}

interface EpssApiRow {
  cve?: string;
  epss?: string;
  percentile?: string;
  date?: string;
}

interface EpssApiResponse {
  status?: string;
  "status-code"?: number;
  data?: EpssApiRow[];
}

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function queryEpssChunk(cves: string[]): Promise<EpssScore[]> {
  const url = `${EPSS_BASE}?cve=${encodeURIComponent(cves.join(","))}`;
  const res = await fetch(url, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok)
    throw new Error(`EPSS query failed: ${res.status} ${res.statusText}`);
  const body = (await res.json()) as EpssApiResponse;
  if (!body || !Array.isArray(body.data))
    throw new Error("EPSS response missing data[]");
  const out: EpssScore[] = [];
  for (const row of body.data) {
    if (!row.cve) continue;
    const epss = parseFloat(row.epss ?? "");
    const percentile = parseFloat(row.percentile ?? "");
    if (Number.isNaN(epss)) continue;
    out.push({
      cve: row.cve.toUpperCase(),
      epss,
      percentile: Number.isNaN(percentile) ? 0 : percentile,
      date: row.date ?? "",
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Render / inject the _epss block. Idempotent: strip any existing _epss
// block first, then append a fresh one. We operate on the raw text (not a
// yaml.dump round-trip) to avoid reformatting the whole proposal -- purely
// additive, every other byte preserved.
// ---------------------------------------------------------------------------

function stripExistingEpss(text: string): string {
  // Remove a top-level `_epss:` block and any leading `# === EPSS ... ===`
  // comment lines, up to the next top-level key (a line starting at column 0
  // that is not indented and not a blank/comment) or EOF.
  const lines = text.split("\n");
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const isEpssComment = /^#\s*=+\s*EPSS\b/.test(line);
    const isEpssKey = /^_epss:\s*$/.test(line);
    if (isEpssComment || isEpssKey) {
      // If it's the comment, the next non-removed top-level construct is the
      // _epss key; consume comment lines then the block.
      if (isEpssComment) {
        // drop this comment line and any immediately-following comment lines
        i += 1;
        while (i < lines.length && /^#/.test(lines[i])) i += 1;
        continue;
      }
      // isEpssKey: drop the key line + all indented child lines.
      i += 1;
      while (i < lines.length) {
        const l = lines[i];
        if (l.trim() === "") {
          i += 1;
          continue;
        }
        // child of the block = starts with whitespace; stop at any
        // unindented (column-0 non-space) line.
        if (/^\s/.test(l)) i += 1;
        else break;
      }
      continue;
    }
    out.push(line);
    i += 1;
  }
  // collapse any trailing blank lines we may have created.
  while (out.length > 0 && out[out.length - 1].trim() === "") out.pop();
  return out.join("\n");
}

function renderEpssBlock(s: EpssScore, queriedAt: string): string {
  return [
    "",
    "# === EPSS exploit-probability (FIRST, additive prioritisation signal) ===",
    "# Higher score = more real-world exploit pressure = author detection first.",
    "_epss:",
    `  score: ${s.epss}`,
    `  percentile: ${s.percentile}`,
    `  date: "${s.date}"`,
    `  cve: "${s.cve}"`,
    `  queried_at: "${queriedAt}"`,
    "",
  ].join("\n");
}

function applyEpss(text: string, s: EpssScore, queriedAt: string): string {
  const base = stripExistingEpss(text).replace(/\s*$/, "\n");
  return base + renderEpssBlock(s, queriedAt);
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface ProposalRec {
  file: string;
  cves: string[];
}

interface RunSummary {
  proposals_scanned: number;
  proposals_with_cve: number;
  cves_unique: number;
  scores_found: number;
  annotated: number;
  skipped_no_score: number;
  high_epss_count: number;
  errors: string[];
  // Distribution buckets for dry-run reporting.
  distribution: Record<string, number>;
  high_epss: { cve: string; score: number; file: string }[];
}

function bucketOf(score: number): string {
  if (score >= 0.5) return ">=0.5";
  if (score >= 0.1) return "0.1-0.5";
  if (score >= 0.01) return "0.01-0.1";
  return "<0.01";
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    proposals_scanned: 0,
    proposals_with_cve: 0,
    cves_unique: 0,
    scores_found: 0,
    annotated: 0,
    skipped_no_score: 0,
    high_epss_count: 0,
    errors: [],
    distribution: { ">=0.5": 0, "0.1-0.5": 0, "0.01-0.1": 0, "<0.01": 0 },
    high_epss: [],
  };

  console.error("=== enrich-epss.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  // --- 1. Walk proposals, collect CVE-bearing files ---
  const files = walkYaml(PROPOSALS_BASE);
  const records: ProposalRec[] = [];
  const allCves = new Set<string>();
  for (const f of files) {
    summary.proposals_scanned += 1;
    let doc: unknown;
    try {
      doc = yaml.load(readFileSync(f, "utf-8"));
    } catch (e) {
      summary.errors.push(`parse ${f}: ${(e as Error).message}`);
      continue;
    }
    const cves = cvesFromDoc(doc);
    if (cves.length === 0) continue; // arxiv/dblp/benchmark/non-CVE -> skip
    summary.proposals_with_cve += 1;
    for (const c of cves) allCves.add(c);
    records.push({ file: f, cves });
  }
  summary.cves_unique = allCves.size;
  console.error(
    `scanned ${summary.proposals_scanned} proposals; ` +
      `${summary.proposals_with_cve} carry a CVE; ` +
      `${summary.cves_unique} unique CVEs.`,
  );

  if (records.length === 0) {
    summary.errors.push(
      "no CVE-bearing proposals found -- nothing to enrich (no-op).",
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::epss-enrich-summary::${JSON.stringify({
        proposals_scanned: summary.proposals_scanned,
        cves_unique: 0,
        scores_found: 0,
        annotated: 0,
        high_epss_count: 0,
      })}`,
    );
    process.exit(2);
  }

  // --- 2. Batch-query EPSS ---
  const scoreByCve = new Map<string, EpssScore>();
  const cveList = [...allCves];
  const chunks = chunk(cveList, EPSS_CHUNK);
  let chunkErrors = 0;
  for (let ci = 0; ci < chunks.length; ci++) {
    const c = chunks[ci];
    try {
      const rows = await queryEpssChunk(c);
      for (const r of rows) scoreByCve.set(r.cve, r);
      if (VERBOSE)
        console.error(
          `  EPSS chunk ${ci + 1}/${chunks.length}: ` +
            `queried ${c.length}, scored ${rows.length}`,
        );
    } catch (e) {
      chunkErrors += 1;
      summary.errors.push(`chunk ${ci + 1}: ${(e as Error).message}`);
      if (VERBOSE)
        console.error(`  EPSS chunk ${ci + 1} failed: ${(e as Error).message}`);
    }
    if (ci < chunks.length - 1) await sleep(RATE_LIMIT_MS);
  }
  // Every chunk failed -> treat as fatal (network/API down).
  if (chunkErrors === chunks.length) {
    console.error("fatal: all EPSS chunks failed -- network/API unavailable.");
    console.log(JSON.stringify(summary, null, 2));
    process.exit(1);
  }
  summary.scores_found = scoreByCve.size;
  console.error(
    `EPSS returned scores for ${summary.scores_found}/${summary.cves_unique} CVEs.`,
  );

  // --- 3. Annotate each CVE-bearing proposal with its highest-EPSS CVE ---
  const queriedAt = new Date().toISOString();
  let processed = 0;
  for (const rec of records) {
    if (processed >= LIMIT) break;
    processed += 1;

    // pick the highest-EPSS scored CVE among this proposal's CVEs.
    let best: EpssScore | null = null;
    for (const cve of rec.cves) {
      const s = scoreByCve.get(cve);
      if (s && (best === null || s.epss > best.epss)) best = s;
    }
    if (!best) {
      summary.skipped_no_score += 1;
      if (VERBOSE)
        console.error(
          `  no-score ${rec.file.replace(REPO_ROOT + "/", "")} ` +
            `(${rec.cves.join(",")})`,
        );
      continue;
    }

    summary.distribution[bucketOf(best.epss)] += 1;
    const isHigh = best.epss > HIGH_EPSS;
    if (isHigh) {
      summary.high_epss_count += 1;
      summary.high_epss.push({
        cve: best.cve,
        score: best.epss,
        file: rec.file.replace(REPO_ROOT + "/", ""),
      });
    }

    if (WRITE) {
      try {
        const orig = readFileSync(rec.file, "utf-8");
        const next = applyEpss(orig, best, queriedAt);
        if (next !== orig) writeFileSync(rec.file, next, "utf-8");
        summary.annotated += 1;
        if (VERBOSE)
          console.error(
            `  annotated ${rec.file.replace(REPO_ROOT + "/", "")} ` +
              `epss=${best.epss} (${best.cve})`,
          );
      } catch (e) {
        summary.errors.push(`write ${rec.file}: ${(e as Error).message}`);
      }
    } else {
      summary.annotated += 1; // would-annotate count in dry-run
      if (VERBOSE)
        console.error(
          `  would annotate ${rec.file.replace(REPO_ROOT + "/", "")} ` +
            `epss=${best.epss} (${best.cve})`,
        );
    }
  }

  // --- report ---
  summary.high_epss.sort((a, b) => b.score - a.score);
  console.error("");
  console.error("--- EPSS score distribution (annotated proposals) ---");
  for (const k of [">=0.5", "0.1-0.5", "0.01-0.1", "<0.01"])
    console.error(`  ${k.padEnd(10)} ${summary.distribution[k]}`);
  if (summary.high_epss.length > 0) {
    console.error("");
    console.error(`--- high-EPSS (>${HIGH_EPSS}) proposals ---`);
    for (const h of summary.high_epss.slice(0, 25))
      console.error(`  ${h.score.toFixed(4)}  ${h.cve}  ${h.file}`);
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::epss-enrich-summary::${JSON.stringify({
      proposals_scanned: summary.proposals_scanned,
      cves_unique: summary.cves_unique,
      scores_found: summary.scores_found,
      annotated: summary.annotated,
      high_epss_count: summary.high_epss_count,
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
