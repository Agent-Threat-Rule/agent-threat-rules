#!/usr/bin/env npx tsx
/**
 * Pull confirmed rules from Community Feed → write to repo → validate + test.
 *
 * Flow:
 *   1. GET /api/atr-rules?since=<last_sync> → fetch new confirmed rules
 *   2. Parse YAML, assign real ID if draft, write to rules/<category>/
 *   3. atr validate + atr test on each new rule
 *   4. Output list of new files for the caller (CI) to commit
 *
 * Usage:
 *   npx tsx scripts/pull-from-tc.ts
 *   npx tsx scripts/pull-from-tc.ts --since 2026-04-01
 *   npx tsx scripts/pull-from-tc.ts --dry-run
 *
 * @module scripts/pull-from-tc
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execSync } from 'node:child_process';

// No built-in endpoint: the engine's reporter works the same way (src/tc-reporter.ts).
const TC_URL = process.env.TC_URL ?? '';
if (!TC_URL) {
  console.error('TC_URL is not set. Point it at the Community Feed endpoint you operate, e.g. TC_URL=https://tc.example.org');
  process.exit(1);
}
const TC_API_KEY = process.env.TC_API_KEY ?? '';
const DRY_RUN = process.argv.includes('--dry-run');
const SINCE_FLAG = process.argv.find((_, i, a) => a[i - 1] === '--since') ?? '';
const RULES_DIR = resolve('rules');
const SYNC_FILE = resolve('data/.tc-last-sync');

function getLastSync(): string {
  if (SINCE_FLAG) return SINCE_FLAG;
  if (existsSync(SYNC_FILE)) {
    return readFileSync(SYNC_FILE, 'utf-8').trim();
  }
  // Default: 7 days ago
  const d = new Date();
  d.setDate(d.getDate() - 7);
  return d.toISOString();
}

function saveLastSync(): void {
  writeFileSync(SYNC_FILE, new Date().toISOString());
}

interface TCRule {
  readonly ruleId: string;
  readonly ruleContent: string;
  readonly source: string;
  readonly publishedAt: string;
}

async function fetchConfirmedRules(since: string): Promise<TCRule[]> {
  const url = `${TC_URL}/api/atr-rules?since=${encodeURIComponent(since)}`;
  const headers: Record<string, string> = { 'Accept': 'application/json' };
  if (TC_API_KEY) headers['Authorization'] = `Bearer ${TC_API_KEY}`;

  const resp = await fetch(url, { headers, signal: AbortSignal.timeout(15_000) });
  if (!resp.ok) throw new Error(`TC API ${resp.status}: ${await resp.text()}`);

  const data = (await resp.json()) as { ok: boolean; data: TCRule[] };
  if (!data.ok) throw new Error('TC API returned ok=false');
  return data.data;
}

function extractField(yaml: string, field: string): string {
  const match = yaml.match(new RegExp(`^${field}:\\s*['\"]?([^'\"\\n]+)`, 'm'));
  return match?.[1]?.trim() ?? '';
}

function getNextRuleId(): number {
  // Find highest existing rule ID
  let maxId = 0;
  // readdirSync, statSync imported at top
  for (const cat of readdirSync(RULES_DIR)) {
    const catDir = join(RULES_DIR, cat);
    if (!statSync(catDir).isDirectory()) continue;
    for (const f of readdirSync(catDir)) {
      const m = f.match(/ATR-2026-(\d{5})/);
      if (m) maxId = Math.max(maxId, parseInt(m[1]!, 10));
    }
  }
  return maxId + 1;
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
}

async function main(): Promise<void> {
  const since = getLastSync();
  console.log(`=== Pull from TC ===`);
  console.log(`TC: ${TC_URL}`);
  console.log(`Since: ${since}`);
  console.log(`Dry run: ${DRY_RUN}\n`);

  const rules = await fetchConfirmedRules(since);

  // Filter to community rules only (skip rules already in repo)
  const existingIds = new Set<string>();
  // readdirSync, statSync imported at top
  for (const cat of readdirSync(RULES_DIR)) {
    const catDir = join(RULES_DIR, cat);
    if (!statSync(catDir).isDirectory()) continue;
    for (const f of readdirSync(catDir)) {
      const content = readFileSync(join(catDir, f), 'utf-8');
      const id = extractField(content, 'id');
      if (id) existingIds.add(id);
    }
  }

  const newRules = rules.filter((r) => {
    const id = extractField(r.ruleContent, 'id');
    return !existingIds.has(id) && r.source !== 'atr'; // skip rules already synced
  });

  console.log(`TC rules total: ${rules.length}`);
  console.log(`Already in repo: ${rules.length - newRules.length}`);
  console.log(`New to pull: ${newRules.length}\n`);

  if (newRules.length === 0) {
    console.log('Nothing new to pull.');
    if (!DRY_RUN) saveLastSync();
    return;
  }

  let nextId = getNextRuleId();
  const written: string[] = [];

  for (const rule of newRules) {
    let content = rule.ruleContent;

    // Replace draft IDs with real sequential IDs
    if (content.includes('ATR-2026-DRAFT') || content.includes('ATR-DRAFT')) {
      const realId = `ATR-2026-${String(nextId).padStart(5, '0')}`;
      content = content.replace(/ATR-2026-DRAFT-[A-Za-z0-9]+|ATR-2026-DRAFT|ATR-DRAFT/g, realId);
      nextId++;
    }

    // Auto-fix common LLM YAML issues: double-quoted regex → single-quoted
    // Double quotes treat \s as escape sequences; single quotes preserve literal backslash
    content = content.replace(
      /^(\s+value:\s*)"((?:[^"\\]|\\.)*)"\s*$/gm,
      (_, prefix, regex) => `${prefix}'${regex.replace(/'/g, "''")}'`,
    );

    const id = extractField(content, 'id');
    const category = extractField(content, 'category') || 'prompt-injection';
    const subcategory = extractField(content, 'subcategory') || slugify(extractField(content, 'title'));

    const catDir = join(RULES_DIR, category);
    if (!existsSync(catDir)) mkdirSync(catDir, { recursive: true });

    const filename = `${id}-${subcategory}.yaml`;
    const filePath = join(catDir, filename);

    if (DRY_RUN) {
      console.log(`[DRY RUN] Would write: ${filePath}`);
      continue;
    }

    writeFileSync(filePath, content);
    console.log(`Written: ${filePath}`);

    // Validate
    try {
      execSync(`node dist/cli.js validate "${filePath}"`, { encoding: 'utf-8', stdio: 'pipe' });
      console.log(`  ✓ Valid`);
    } catch (e: unknown) {
      const err = e as { stdout?: string; stderr?: string; message?: string };
      console.log(`  ✗ Invalid — removing (${(err.stderr || err.stdout || err.message || '').slice(0, 120)})`);
      unlinkSync(filePath);
      continue;
    }

    written.push(filePath);
  }

  console.log(`\n${written.length} rules pulled and validated.`);

  if (!DRY_RUN) {
    saveLastSync();
    // Output file list for CI to use
    if (written.length > 0) {
      writeFileSync('data/.tc-pulled-files.txt', written.join('\n'));
    }
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
