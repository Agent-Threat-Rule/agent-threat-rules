#!/usr/bin/env npx tsx
/**
 * sync-agent-attack-corpora.ts
 *
 * Vendors human-shaped AGENT attack corpora into data/test-corpora/ for the
 * FN-mine lane (scripts/fn-mine-llm.ts). HackAPrompt (2023) and the self-built
 * PINT set are exhausted: the lane's 2026-10 run proposed 40 candidates and
 * none recovered 8 misses. These corpora attack an agent that holds tools, and
 * reach it through a tool's output rather than the user's prompt.
 *
 * Sources (licenses read from each dataset card at the pinned revision; the
 * sync refuses to write a corpus whose card does not declare the expected one):
 *
 *   microsoft/llmail-inject-challenge (MIT). Emails written by challenge
 *     participants to make an email agent call send_email. Kept: submissions
 *     that met all five objectives (retrieved, undetected, tool called, right
 *     recipient, right body), one row per distinct email, spread across the
 *     phase/level grid. Read from data/raw_submissions_phase{1,2}.jsonl
 *     (~1.9 GB, streamed line by line, never held in memory).
 *
 *   perplexity-ai/browsesafe-bench (MIT). HTML pages with a hidden prompt
 *     injection, test split. LLM- and template-generated, not human-written —
 *     recorded in the registry note. Kept: attack pages, each projected to the
 *     text units no benign page of the split holds (see attackProjection), in
 *     content-hash order until the 5 MB file budget. Read through the Hugging
 *     Face datasets-server rows API, which serves the main revision, so the
 *     sync checks main is still the pinned revision before and after.
 *
 * Evaluated and not vendored: see NOT_VENDORED in scripts/lib/agent-attack-corpora.ts.
 *
 * Usage:
 *   npx tsx scripts/sync-agent-attack-corpora.ts                      # dry-run
 *   npx tsx scripts/sync-agent-attack-corpora.ts --write              # write corpora
 *   npx tsx scripts/sync-agent-attack-corpora.ts --source llmail-inject --write
 *
 * No token is needed: all three endpoints serve public datasets anonymously.
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, license or revision mismatch)
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { Readable } from 'node:stream';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { parseArgs } from 'node:util';
import {
  BROWSESAFE,
  LLMAIL,
  MAX_CORPUS_BYTES,
  MAX_PROJECTION_CHARS,
  MAX_ROWS,
  browsesafeRows,
  cardLicenseLine,
  corpusDocument,
  licenseProblem,
  llmailRows,
  llmailSucceeded,
  sourceMarkdown,
  stratifiedSample,
  withinBudget,
  type BrowsesafeRawRow,
  type CorpusDocMeta,
  type CorpusRow,
  type LlmailRawRow,
  type UpstreamDataset,
} from './lib/agent-attack-corpora.js';

const REPO_ROOT = process.cwd();
const OUT_DIR = 'data/test-corpora';
const HUB = 'https://huggingface.co';
const ROWS_API = 'https://datasets-server.huggingface.co/rows';
const ROWS_PAGE = 100;

const resolveUrl = (d: UpstreamDataset, file: string): string =>
  `${HUB}/datasets/${d.repo}/resolve/${d.revision}/${file}`;

const RETRIES = 5;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** GET, retrying a rate limit or server error with backoff (the rows API rate-limits at ~30 pages). */
async function fetchOk(url: string, attempt = 0): Promise<Response> {
  const res = await fetch(url);
  if (res.ok && res.body) return res;
  const retryable = res.status === 429 || res.status >= 500;
  if (!retryable || attempt >= RETRIES) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  const wait = Number(res.headers.get('retry-after')) * 1000 || 2 ** attempt * 5000;
  console.log(`[sync]   HTTP ${res.status}, retrying in ${Math.round(wait / 1000)}s`);
  await sleep(wait);
  return fetchOk(url, attempt + 1);
}

/** The card's license line, after checking it permits vendoring. */
async function checkedLicense(d: UpstreamDataset): Promise<string> {
  const readme = await (await fetchOk(resolveUrl(d, 'README.md'))).text();
  const problem = licenseProblem(readme, d.license);
  if (problem) throw new Error(`${d.repo}@${d.revision}: ${problem}; not vendoring it.`);
  return cardLicenseLine(readme) ?? '';
}

async function* jsonLines(url: string): AsyncGenerator<unknown> {
  const res = await fetchOk(url);
  const lines = createInterface({ input: Readable.fromWeb(res.body as unknown as WebReadableStream) });
  for await (const line of lines) {
    if (line.trim()) yield JSON.parse(line);
  }
}

const LLMAIL_FILES = ['data/raw_submissions_phase1.jsonl', 'data/raw_submissions_phase2.jsonl'];

async function* llmailRaw(): AsyncGenerator<{ row: LlmailRawRow; phase: string }> {
  for (const file of LLMAIL_FILES) {
    const phase = /phase\d/.exec(file)?.[0] ?? 'phase?';
    console.log(`[sync]   streaming ${file}`);
    for await (const row of jsonLines(resolveUrl(LLMAIL, file))) yield { row: row as LlmailRawRow, phase };
  }
}

/** Successful LLMail submissions. The files hold ~460K rows; only ~3.3K succeeded, so only those are kept. */
async function collectLlmail(): Promise<readonly CorpusRow[]> {
  const succeeded: { row: LlmailRawRow; phase: string }[] = [];
  for await (const r of llmailRaw()) if (llmailSucceeded(r.row)) succeeded.push(r);
  return llmailRows(succeeded);
}

async function hubRevision(d: UpstreamDataset): Promise<string> {
  const info = (await (await fetchOk(`${HUB}/api/datasets/${d.repo}`)).json()) as { sha?: string };
  return info.sha ?? '';
}

async function assertMainIsPinned(d: UpstreamDataset): Promise<void> {
  const sha = await hubRevision(d);
  if (sha !== d.revision) {
    throw new Error(`${d.repo}: main is ${sha}, pinned ${d.revision}. The rows API serves main; re-pin before syncing.`);
  }
}

interface RowsPage {
  readonly rows?: readonly { readonly row: BrowsesafeRawRow; readonly truncated_cells?: readonly string[] }[];
  readonly num_rows_total?: number;
}

async function browsesafeSplit(split: string): Promise<readonly BrowsesafeRawRow[]> {
  const out: BrowsesafeRawRow[] = [];
  for (let offset = 0, total = Infinity; offset < total; offset += ROWS_PAGE) {
    const q = `dataset=${encodeURIComponent(BROWSESAFE.repo)}&config=default&split=${split}&offset=${offset}&length=${ROWS_PAGE}`;
    const page = (await (await fetchOk(`${ROWS_API}?${q}`)).json()) as RowsPage;
    total = page.num_rows_total ?? 0;
    for (const r of page.rows ?? []) {
      if ((r.truncated_cells ?? []).length > 0) throw new Error(`rows API truncated row ${offset}: refusing a partial page`);
      out.push(r.row);
    }
  }
  return out;
}

async function collectBrowsesafe(): Promise<readonly CorpusRow[]> {
  await assertMainIsPinned(BROWSESAFE);
  const rows = await browsesafeSplit('test');
  await assertMainIsPinned(BROWSESAFE);
  console.log(`[sync]   test split: ${rows.length} rows`);
  return browsesafeRows(rows, 'test');
}

interface SourcePlan {
  readonly dataset: UpstreamDataset;
  readonly files: readonly string[];
  readonly filter: string;
  readonly collect: () => Promise<readonly CorpusRow[]>;
}

const SOURCES: readonly SourcePlan[] = [
  {
    dataset: LLMAIL,
    files: LLMAIL_FILES,
    filter:
      'all five objectives true (email.retrieved, defense.undetected, exfil.sent, exfil.destination, ' +
      `exfil.content); deduplicated on subject+body; stratified by phase/level in sha256 order; at most ${MAX_ROWS}`,
    collect: collectLlmail,
  },
  {
    dataset: BROWSESAFE,
    files: ['test.parquet (via datasets-server rows API, split=test)'],
    filter:
      "label == 'yes'; page projected to text units absent from every benign page of the split; " +
      `projections over ${MAX_PROJECTION_CHARS} chars skipped; sha256 order; at most ${MAX_ROWS} and ${MAX_CORPUS_BYTES} bytes`,
    collect: collectBrowsesafe,
  },
];

async function syncOne(plan: SourcePlan, write: boolean, retrieved: string): Promise<void> {
  const { dataset } = plan;
  console.log(`[sync] ${dataset.id} <- ${dataset.repo}@${dataset.revision}`);
  const licenseLine = await checkedLicense(dataset);
  const candidates = await plan.collect();
  const rows = withinBudget(stratifiedSample(candidates, MAX_ROWS), MAX_CORPUS_BYTES);
  console.log(`[sync]   ${candidates.length} rows pass the filter, ${rows.length} kept`);
  if (!write) return;
  const meta: CorpusDocMeta = { dataset, retrieved, filter: plan.filter };
  const dir = join(REPO_ROOT, OUT_DIR, dataset.id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'corpus.json'), `${JSON.stringify(corpusDocument(rows, meta), null, 2)}\n`);
  writeFileSync(join(dir, 'SOURCE.md'), sourceMarkdown(meta, licenseLine, plan.files, rows.length));
  console.log(`[sync]   wrote ${OUT_DIR}/${dataset.id}/corpus.json and SOURCE.md`);
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: { write: { type: 'boolean', default: false }, source: { type: 'string' } },
  });
  const wanted = values.source ? SOURCES.filter((s) => s.dataset.id === values.source) : SOURCES;
  if (wanted.length === 0) {
    throw new Error(`unknown source "${values.source}" -- known: ${SOURCES.map((s) => s.dataset.id).join(', ')}`);
  }
  console.log(`=== sync-agent-attack-corpora.ts (${values.write ? 'WRITE' : 'dry-run'}) ===`);
  const retrieved = new Date().toISOString().slice(0, 10);
  for (const plan of wanted) await syncOne(plan, values.write === true, retrieved);
}

main().catch((err) => {
  console.error(`[sync] FATAL: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
