#!/usr/bin/env tsx
/**
 * Reads stats.json and rewrites every user-facing surface that depends on it.
 * Runs in CI on every rules-merge release, and locally via `npm run sync:stats`.
 *
 * Fails loud (non-zero exit) if any derived file cannot be updated, so CI
 * blocks the release rather than shipping inconsistent numbers.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');

interface Stats {
  version: string;
  lastUpdated: string;
  ruleCount: { total: number; effective?: number; stable: number; experimental: number; draft: number };
  spec: { version: string; status: string; doi: string };
  benchmarks: {
    garak: { recall: number; samples: number; atr_version?: string };
    skill: { recall: number; precision: number; samples: number };
    pint: { recall: number; precision: number; samples: number };
    hackaprompt: { recall: number; baselineRecall: number; samples: number };
    benign: { fpRate: number; samples: number };
  };
  ecosystem: { skillsScanned: number; confirmedMalware: number };
  distribution: { npm: { downloads30d: number }; githubStars: number };
  coverage: {
    owaspAgentic: { display: string };
    safeMcp: { display: string; percentage: number };
  };
  adoption: {
    externalOrgsMerged: number;
    externalPRMergesTotal: number;
    tier1Institutions: number;
  };
  license: string;
}

function loadStats(): Stats {
  const raw = readFileSync(join(REPO_ROOT, 'stats.json'), 'utf8');
  return JSON.parse(raw) as Stats;
}

interface SyncResult { file: string; changed: boolean; ops: string[]; }

function syncFile(rel: string, transform: (text: string) => string): SyncResult {
  const path = join(REPO_ROOT, rel);
  if (!existsSync(path)) return { file: rel, changed: false, ops: ['skip: not found'] };
  const before = readFileSync(path, 'utf8');
  const after = transform(before);
  const changed = before !== after;
  if (changed) writeFileSync(path, after);
  return { file: rel, changed, ops: changed ? ['written'] : ['unchanged'] };
}

function replaceBadge(text: string, name: string, value: string): string {
  const re = new RegExp(`(\\[!\\[${escapeReg(name)}\\]\\(https:\\/\\/img\\.shields\\.io\\/badge\\/)[^)]+(\\))`);
  return text.replace(re, (_m, p1, p2) => `${p1}${name.replace(/ /g, '_')}-${value}${p2}`);
}

function escapeReg(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function syncReadme(s: Stats): SyncResult {
  return syncFile('README.md', (text) => {
    let out = text;
    out = out.replace(
      /(\[!\[Rules\]\(https:\/\/img\.shields\.io\/badge\/rules-)\d+(-blue)/,
      `$1${s.ruleCount.total}$2`,
    );
    out = out.replace(
      /(\[!\[Garak Recall\]\(https:\/\/img\.shields\.io\/badge\/garak_recall-)[\d.]+%25(-brightgreen)/,
      `$1${s.benchmarks.garak.recall}%25$2`,
    );
    out = out.replace(
      /(\[!\[SKILL\.md Recall\]\(https:\/\/img\.shields\.io\/badge\/SKILL\.md_recall-)[\d.]+%25(-brightgreen)/,
      `$1${s.benchmarks.skill.recall}%25$2`,
    );
    out = out.replace(
      /(\[!\[Wild Scan\]\(https:\/\/img\.shields\.io\/badge\/wild_scan-)[\d,]+_skills(-blue)/,
      `$1${s.ecosystem.skillsScanned.toLocaleString('en-US').replace(/,/g, '%2C')}_skills$2`,
    );
    out = out.replace(
      /(\[!\[npm\]\(https:\/\/img\.shields\.io\/npm\/v\/agent-threat-rules[^\)]*\)\]\([^)]+\))/,
      `$1`,
    );
    return out;
  });
}

function syncCitation(s: Stats): SyncResult {
  return syncFile('CITATION.cff', (text) => {
    let out = text;
    out = out.replace(/^version: ".*"$/m, `version: "${s.version}"`);
    out = out.replace(/^date-released: ".*"$/m, `date-released: "${s.lastUpdated}"`);
    // effective, not total: `total` counts rule FILES, and src/engine.ts skips
    // status: draft | deprecated before the lane gate, so those rules fire in no
    // lane at all. Citing the file count overstates what the engine runs.
    out = out.replace(/\b\d{2,4} rules across \d+ threat\b/, `${s.ruleCount.effective ?? s.ruleCount.total} rules across 10 threat`);
    out = out.replace(/\(\d+\.\d+% recall on the\b/, `(${s.benchmarks.garak.recall}% recall on the`);
    // The ATR version in this sentence was NOT synced, so the abstract cited
    // "91.5% ... ATR 3.5.0" — a recall from one version attributed to another.
    // The recall and the version it was measured on have to move together.
    out = out.replace(
      /garak in-the-wild jailbreak benchmark, \d+ prompts, ATR [\w.-]+\)/,
      `garak in-the-wild jailbreak benchmark, ${s.benchmarks.garak.samples} prompts, ATR ${s.benchmarks.garak.atr_version ?? s.version})`,
    );
    out = out.replace(/garak in-the-wild jailbreak benchmark, \d+ prompts\)/, `garak in-the-wild jailbreak benchmark, ${s.benchmarks.garak.samples} prompts)`);
    out = out.replace(/on a \d+-sample benign corpus/, `on a ${s.benchmarks.benign.samples}-sample benign corpus`);
    return out;
  });
}

/**
 * The npm package description is deliberately NOT synced.
 *
 * It used to be rebuilt here from `ruleCount.total` and `benchmarks.garak.recall`,
 * which looks like freshness and is the opposite. A description only reaches the
 * world when a version is published; between publishes npm keeps serving whatever
 * the last publish carried, so the numbers on the registry page were pinned to an
 * arbitrary past release while this file kept "correcting" them locally. The
 * registry listing spent months advertising 751 rules and 97.2% garak recall
 * against a corpus that had grown to 780 and a figure honestly re-measured down
 * to 91.5%.
 *
 * #411 removed the numbers from the description for that reason. This function
 * existed to put them back on the next run — which is why it is now a no-op
 * rather than deleted: an empty implementation with this comment is harder to
 * reintroduce by accident than an absent one.
 *
 * Numbers belong where they can be regenerated on read: the README badges,
 * stats.json, and the site. Not in a string frozen at publish time.
 */
function syncPackageJson(_s: Stats): SyncResult {
  return { file: 'package.json', changed: false, ops: ['skip: description is intentionally number-free, see #411'] };
}

function syncQuickStart(s: Stats): SyncResult {
  return syncFile('docs/quick-start.md', (text) => {
    return text.replace(/Rules loaded: \d+/, `Rules loaded: ${s.ruleCount.total}`);
  });
}

// Crosswalk mapping docs hardcode the live corpus rule count in their header.
// Keep that single number synced with the live total so audit-mappings.ts never
// flags them stale. We replace ONLY the first "<N> rules" occurrence (the header
// corpus count); body coverage counts ("12 rules across ...", "462-rule corpus")
// and version strings are left untouched. The legacy v1.0.0 OWASP-MAPPING.md is
// intentionally excluded — its 108-rule body is a frozen snapshot, not the live corpus.
const CROSSWALK_DOCS = [
  'SAFE-MCP-MAPPING.md', 'FIVE-EYES-MAPPING.md', 'OWASP-AST10-MAPPING.md', 'NSA-MCP-MAPPING.md',
  'ETSI-TS-104223-MAPPING.md', 'FINOS-AI-GOVERNANCE-MAPPING.md', 'MCP-38-MAPPING.md',
  'MITRE-ATLAS-MAPPING.md', 'OWASP-AGENTIC-MAPPING.md', 'OWASP-AGENTIC-MATURITY-MAPPING.md',
  'OWASP-AISVS-MAPPING.md', 'OWASP-AIVSS-MAPPING.md',
] as const;

function syncCrosswalkDocs(s: Stats): SyncResult[] {
  return CROSSWALK_DOCS.map((name) =>
    syncFile(`docs/${name}`, (text) => text.replace(/\b\d{2,4}(\s+rules)/, `${s.ruleCount.total}$1`)),
  );
}

const main = (): void => {
  const stats = loadStats();
  const results: SyncResult[] = [
    syncReadme(stats),
    syncCitation(stats),
    syncPackageJson(stats),
    syncQuickStart(stats),
    ...syncCrosswalkDocs(stats),
  ];
  const filesystemRuleCount = countRuleFiles();
  if (filesystemRuleCount !== stats.ruleCount.total) {
    console.error(
      `[sync-stats] FATAL: stats.json says ${stats.ruleCount.total} rules; filesystem has ${filesystemRuleCount} *.yaml files in rules/.`,
    );
    process.exit(2);
  }
  const failed = results.filter((r) => r.ops.includes('skip: not found') && !r.file.startsWith('docs/'));
  if (failed.length > 0) {
    console.error('[sync-stats] FATAL: required surfaces missing:', failed.map((r) => r.file));
    process.exit(3);
  }
  for (const r of results) console.log(`[sync-stats] ${r.changed ? 'updated' : 'noop'}  ${r.file}`);
  console.log(`[sync-stats] OK · version=${stats.version} · rules=${stats.ruleCount.total}`);
};

function countRuleFiles(): number {
  const out = execSync('find rules -name "*.yaml" -type f -exec grep -l "^id: ATR-" {} \\; | wc -l', { cwd: REPO_ROOT })
    .toString()
    .trim();
  return Number.parseInt(out, 10);
}

main();
