#!/usr/bin/env npx tsx
/**
 * eval-academic-raw.ts
 *
 * Fetch the raw upstream CSV corpora for three academic adversarial-prompt
 * benchmarks and evaluate ATR engine recall against each.
 *
 * Distinct from scripts/sync-advbench.ts which fetches the same upstream
 * data but generates RULE PROPOSALS (proposals/<source>/<slug>.proposal.yaml)
 * for human review. This script fetches the same data and instead writes
 * one MEASUREMENT per source under data/measurements/<source>/.
 *
 * Sources:
 *   - advbench       (llm-attacks/llm-attacks, MIT)
 *                    520 harmful behaviors
 *   - harmbench      (centerforaisafety/HarmBench, MIT)
 *                    ~400 behaviors across multiple categories
 *   - jailbreakbench (JailbreakBench/jailbreakbench, MIT)
 *                    100 behaviors (10 harm categories × 10 prompts)
 *
 * License: All three datasets are MIT-licensed and may be re-distributed.
 * This script does NOT commit the raw corpora to the repo — it fetches
 * upstream every run. The MEASUREMENT (recall summary) is what we commit;
 * the raw probe text is upstream's to maintain.
 *
 * Output:
 *   - One Measurement per source under data/measurements/<source>/
 *   - Per-source recall summary on stdout
 *
 * Network: requires outbound HTTPS to raw.githubusercontent.com and
 * huggingface.co. Skips a source on fetch failure with a ::warning::
 * line rather than failing the whole run.
 *
 * Usage:
 *   npx tsx scripts/eval-academic-raw.ts                # all three
 *   npx tsx scripts/eval-academic-raw.ts --source advbench
 */

import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from '../src/engine.js';
import type { AgentEvent } from '../src/types.js';
import { writeMeasurement } from '../src/measurement/write.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');

// ─── Source registry ───────────────────────────────────────────────────────

interface SourceDef {
  id: 'advbench' | 'harmbench' | 'jailbreakbench';
  url: string;
  license: string;
  /** Possible column names for the harmful prompt text (case-insensitive). */
  behaviorColumns: readonly string[];
  /** Possible column names for the category label (optional). */
  categoryColumns: readonly string[];
  notes: string;
}

const SOURCES: readonly SourceDef[] = [
  {
    id: 'advbench',
    url: 'https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv',
    license: 'MIT (llm-attacks/llm-attacks)',
    behaviorColumns: ['goal', 'behavior', 'prompt'],
    categoryColumns: ['category', 'topic', 'class'],
    notes: 'AdvBench harmful_behaviors.csv (520 prompts). Academic adversarial.',
  },
  {
    id: 'harmbench',
    url: 'https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv',
    license: 'MIT (centerforaisafety/HarmBench)',
    behaviorColumns: ['Behavior', 'behavior', 'prompt'],
    categoryColumns: ['SemanticCategory', 'category', 'topic'],
    notes: 'HarmBench harmbench_behaviors_text_all.csv (~400 prompts). Academic adversarial.',
  },
  {
    id: 'jailbreakbench',
    url: 'https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/harmful-behaviors.csv',
    license: 'MIT (JailbreakBench/JBB-Behaviors)',
    behaviorColumns: ['Goal', 'goal', 'behavior', 'prompt'],
    categoryColumns: ['Category', 'category'],
    notes: 'JailbreakBench JBB-Behaviors harmful-behaviors.csv (100 prompts). Academic adversarial.',
  },
];

// ─── Args ───────────────────────────────────────────────────────────────────

function parseArgs(): { sources: readonly SourceDef[] } {
  const args = process.argv.slice(2);
  const idx = args.indexOf('--source');
  if (idx >= 0 && args[idx + 1]) {
    const id = args[idx + 1];
    const s = SOURCES.find((x) => x.id === id);
    if (!s) {
      console.error(`Unknown source: ${id}. Known: ${SOURCES.map((x) => x.id).join(', ')}`);
      process.exit(2);
    }
    return { sources: [s] };
  }
  return { sources: SOURCES };
}

// ─── CSV parsing ────────────────────────────────────────────────────────────

/**
 * Minimal RFC 4180-aware CSV parser sufficient for the three target corpora.
 * Handles quoted fields with embedded commas, quoted newlines (\r\n / \n),
 * and escaped double quotes ("").
 *
 * Returns rows as string[][]; first row is the header.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let cur: string[] = [];
  let cell = '';
  let i = 0;
  let inQuotes = false;
  const len = text.length;

  while (i < len) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      cell += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (ch === ',') {
      cur.push(cell);
      cell = '';
      i += 1;
      continue;
    }
    if (ch === '\r') {
      if (text[i + 1] === '\n') {
        cur.push(cell);
        rows.push(cur);
        cur = [];
        cell = '';
        i += 2;
        continue;
      }
      cur.push(cell);
      rows.push(cur);
      cur = [];
      cell = '';
      i += 1;
      continue;
    }
    if (ch === '\n') {
      cur.push(cell);
      rows.push(cur);
      cur = [];
      cell = '';
      i += 1;
      continue;
    }
    cell += ch;
    i += 1;
  }
  // Final cell / row if file did not end with newline.
  if (cell.length > 0 || cur.length > 0) {
    cur.push(cell);
    rows.push(cur);
  }
  // Drop trailing empty row (common after a final newline).
  if (rows.length > 0 && rows[rows.length - 1].every((c) => c === '')) rows.pop();
  return rows;
}

function pickColumn(headers: readonly string[], candidates: readonly string[]): number {
  const lower = headers.map((h) => h.trim().toLowerCase());
  for (const c of candidates) {
    const idx = lower.indexOf(c.toLowerCase());
    if (idx >= 0) return idx;
  }
  return -1;
}

// ─── Fetch + eval ───────────────────────────────────────────────────────────

interface FetchResult {
  prompts: { text: string; category: string }[];
  fetchedAt: string;
  contentLength: number;
}

async function fetchCsv(url: string): Promise<string> {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
  return res.text();
}

async function fetchSource(source: SourceDef): Promise<FetchResult | null> {
  try {
    console.log(`  fetching ${source.url}`);
    const csv = await fetchCsv(source.url);
    const rows = parseCsv(csv);
    if (rows.length < 2) {
      console.warn(`::warning::${source.id}: CSV had ${rows.length} rows, skipping`);
      return null;
    }
    const headers = rows[0];
    const behaviorIdx = pickColumn(headers, source.behaviorColumns);
    if (behaviorIdx < 0) {
      console.warn(
        `::warning::${source.id}: no behavior column found in headers ${headers.join(',')} — wanted one of ${source.behaviorColumns.join(',')}`,
      );
      return null;
    }
    const categoryIdx = pickColumn(headers, source.categoryColumns);
    const prompts: { text: string; category: string }[] = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      const text = (row[behaviorIdx] ?? '').trim();
      if (text.length < 4) continue;
      const category = categoryIdx >= 0 ? (row[categoryIdx] ?? 'unknown').trim() : 'unknown';
      prompts.push({ text, category });
    }
    return { prompts, fetchedAt: new Date().toISOString(), contentLength: csv.length };
  } catch (err) {
    console.warn(
      `::warning::${source.id}: fetch failed — ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }
}

async function evalSource(source: SourceDef, fetch: FetchResult, engine: ATREngine): Promise<void> {
  let matched = 0;
  const byCategory: Record<string, { total: number; matched: number }> = {};

  for (const p of fetch.prompts) {
    byCategory[p.category] = byCategory[p.category] ?? { total: 0, matched: 0 };
    byCategory[p.category].total += 1;
    const event: AgentEvent = {
      type: 'llm_io',
      content: p.text,
      timestamp: new Date().toISOString(),
      fields: { user_input: p.text },
    };
    const matches = engine.evaluate(event);
    if (matches.length > 0) {
      matched += 1;
      byCategory[p.category].matched += 1;
    }
  }

  const total = fetch.prompts.length;
  const recall = total > 0 ? matched / total : 0;
  const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);

  console.log(`\n[${source.id}] ${matched}/${total} = ${(recall * 100).toFixed(1)}% recall`);
  const sortedCats = Object.entries(byCategory).sort((a, b) => b[1].total - a[1].total);
  for (const [cat, stats] of sortedCats.slice(0, 8)) {
    const catRecall = stats.matched / stats.total;
    console.log(`  ${cat}: ${stats.matched}/${stats.total} (${(catRecall * 100).toFixed(0)}%)`);
  }
  if (sortedCats.length > 8) {
    console.log(`  ... and ${sortedCats.length - 8} more categories`);
  }

  const breakdownCats: Record<string, { total: number; matched: number; recall: number }> = {};
  for (const [c, s] of Object.entries(byCategory)) {
    breakdownCats[c] = { total: s.total, matched: s.matched, recall: s.total > 0 ? s.matched / s.total : 0 };
  }

  const { measurementPath } = writeMeasurement(
    {
      source: source.id,
      source_version: `upstream-${fetch.fetchedAt.slice(0, 10)}`,
      source_url: source.url,
      samples: total,
      metrics: {
        recall,
        precision: 1,
        f1,
        fp_rate: 0,
      },
      confusion: {
        tp: matched,
        fp: 0,
        tn: 0,
        fn: total - matched,
      },
      breakdown: {
        by_category: breakdownCats,
        fetched_at: fetch.fetchedAt,
        upstream_bytes: fetch.contentLength,
        license: source.license,
      },
      notes: `${source.notes} License: ${source.license}. 100% adversarial — fp_rate undefined and recorded as 0 by convention. Corpus fetched live from upstream at ${fetch.fetchedAt} (not committed to repo).`,
    },
    { force: true },
  );
  console.log(`  Measurement: ${measurementPath}`);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { sources } = parseArgs();

  console.log('Loading ATR engine...');
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  const ruleCount = await engine.loadRules();
  console.log(`Loaded ${ruleCount} rules\n`);

  for (const source of sources) {
    console.log(`=== ${source.id} ===`);
    const fetched = await fetchSource(source);
    if (fetched === null) continue;
    console.log(`  parsed ${fetched.prompts.length} prompts (${fetched.contentLength} bytes)`);
    await evalSource(source, fetched, engine);
  }

  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
