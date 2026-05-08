#!/usr/bin/env npx tsx
/**
 * apply-nist-mapping.ts
 *
 * Reverse of expand-nist-mapping: reads proposals/nist/<rule-id>.proposal.yaml
 * and patches the corresponding rule file's `compliance.nist_ai_rmf` block.
 *
 * Safety:
 * - Only modifies rules WITHOUT existing nist_ai_rmf mapping (won't overwrite manual)
 * - Validates YAML parses after patch
 * - Atomic write (tmp file + rename)
 * - --dry-run shows diff without writing
 * - --rule-id <ID> applies single rule only
 *
 * Usage:
 *   # Dry-run on 5 rules
 *   npx tsx scripts/apply-nist-mapping.ts --limit 5 --dry-run
 *
 *   # Apply all 261 proposals
 *   npx tsx scripts/apply-nist-mapping.ts --all
 *
 *   # Apply specific rule
 *   npx tsx scripts/apply-nist-mapping.ts --rule-id ATR-2026-00080
 */

import {
  readFileSync,
  writeFileSync,
  readdirSync,
  statSync,
  existsSync,
  renameSync,
} from 'node:fs';
import { resolve, basename, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const args = process.argv.slice(2);
const getArg = (flag: string): string | undefined => {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
};
const hasFlag = (flag: string): boolean => args.includes(flag);

const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const PROPOSALS_DIR = resolve(REPO_ROOT, getArg('--proposals') ?? 'proposals/nist');

const DRY_RUN = hasFlag('--dry-run');
const ALL = hasFlag('--all');
const LIMIT = parseInt(getArg('--limit') ?? '0', 10);
const RULE_ID = getArg('--rule-id');
const FORCE = hasFlag('--force'); // overwrite existing nist_ai_rmf mapping

function walkYaml(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...walkYaml(full));
    } else if (st.isFile() && entry.endsWith('.yaml')) {
      out.push(full);
    }
  }
  return out;
}

interface Proposal {
  rule_id: string;
  rule_path: string;
  rule_title: string;
  proposed_mapping: any[];
  raw_yaml: string;
  provenance: any;
  qa_status: string;
}

function loadProposals(): Proposal[] {
  if (!existsSync(PROPOSALS_DIR)) {
    console.error(`Proposals dir not found: ${PROPOSALS_DIR}`);
    process.exit(1);
  }
  const files = readdirSync(PROPOSALS_DIR).filter((f) => f.endsWith('.proposal.yaml'));
  const out: Proposal[] = [];
  for (const f of files) {
    try {
      const content = readFileSync(join(PROPOSALS_DIR, f), 'utf8');
      const parsed = yaml.load(content) as Proposal;
      out.push(parsed);
    } catch (e) {
      console.warn(`  ⚠ Failed to parse ${f}: ${(e as Error).message}`);
    }
  }
  return out;
}

function findRuleFile(ruleId: string): string | null {
  const allRules = walkYaml(RULES_DIR);
  for (const path of allRules) {
    if (path.includes(ruleId)) return path;
  }
  return null;
}

/**
 * Patch the rule YAML to insert/replace the compliance.nist_ai_rmf block.
 * Strategy: text-level patching to preserve formatting, comments, and ordering.
 *
 * Insertion location: under `compliance:` block. If `compliance:` doesn't exist,
 * insert before `tags:` block (which is a stable anchor in ATR rules).
 */
function patchRuleYaml(originalContent: string, mappingYaml: string, ruleId: string): {
  patched: string;
  alreadyHadMapping: boolean;
  inserted: boolean;
} {
  const lines = originalContent.split('\n');
  const out: string[] = [];

  // Determine if compliance.nist_ai_rmf exists
  const hasNistMapping = /^\s*nist_ai_rmf:/m.test(originalContent);
  const hasCompliance = /^compliance:/m.test(originalContent);

  // If has nist_ai_rmf and not --force, skip
  if (hasNistMapping && !FORCE) {
    return { patched: originalContent, alreadyHadMapping: true, inserted: false };
  }

  // Build the indented mapping block (each line of mappingYaml gets 2 spaces of indent)
  const indentedMapping = mappingYaml
    .trim()
    .split('\n')
    .map((line) => `    ${line}`)
    .join('\n');

  if (hasCompliance) {
    // Insert nist_ai_rmf as first child under compliance:
    // Find the `compliance:` line, insert right after it
    let inserted = false;
    for (let i = 0; i < lines.length; i++) {
      out.push(lines[i]);
      if (!inserted && /^compliance:\s*$/.test(lines[i])) {
        out.push(`  nist_ai_rmf:`);
        out.push(indentedMapping);
        inserted = true;
      }
    }
    return { patched: out.join('\n'), alreadyHadMapping: false, inserted };
  } else {
    // No compliance: block. Insert a full compliance: block before `tags:`
    let inserted = false;
    for (let i = 0; i < lines.length; i++) {
      if (!inserted && /^tags:\s*$/.test(lines[i])) {
        out.push(`compliance:`);
        out.push(`  nist_ai_rmf:`);
        out.push(indentedMapping);
        inserted = true;
      }
      out.push(lines[i]);
    }
    if (!inserted) {
      // No `tags:` either — append at end (rare)
      out.push(`compliance:`);
      out.push(`  nist_ai_rmf:`);
      out.push(indentedMapping);
      inserted = true;
    }
    return { patched: out.join('\n'), alreadyHadMapping: false, inserted };
  }
}

function applyProposal(proposal: Proposal): {
  status: 'applied' | 'skipped-existing' | 'rule-not-found' | 'parse-failed';
  rulePath?: string;
  diff?: string;
} {
  const rulePath = findRuleFile(proposal.rule_id);
  if (!rulePath) {
    return { status: 'rule-not-found' };
  }

  const original = readFileSync(rulePath, 'utf8');
  const { patched, alreadyHadMapping, inserted } = patchRuleYaml(
    original,
    proposal.raw_yaml,
    proposal.rule_id
  );

  if (alreadyHadMapping) {
    return { status: 'skipped-existing', rulePath };
  }

  if (!inserted) {
    return { status: 'parse-failed', rulePath };
  }

  // Validate patched YAML still parses
  try {
    yaml.load(patched);
  } catch (e) {
    console.error(`  ⚠ Patched YAML failed to parse for ${proposal.rule_id}: ${(e as Error).message}`);
    return { status: 'parse-failed', rulePath };
  }

  // Compute diff for display
  const diff = `--- ${rulePath}\n+++ patched\n${patched
    .split('\n')
    .filter((l) => !original.includes(l))
    .map((l) => `+ ${l}`)
    .slice(0, 20)
    .join('\n')}`;

  if (!DRY_RUN) {
    // Atomic write: tmp + rename
    const tmpPath = rulePath + '.tmp';
    writeFileSync(tmpPath, patched);
    renameSync(tmpPath, rulePath);
  }

  return { status: 'applied', rulePath, diff };
}

async function main() {
  console.log('─'.repeat(60));
  console.log('ATR — Apply NIST AI RMF mapping proposals to rule files');
  console.log(`Mode: ${DRY_RUN ? 'DRY-RUN (no file writes)' : 'WRITE'}`);
  console.log(`Force overwrite: ${FORCE}`);
  console.log('─'.repeat(60));

  let proposals = loadProposals();
  console.log(`\nLoaded ${proposals.length} proposals from ${PROPOSALS_DIR}`);

  if (RULE_ID) {
    proposals = proposals.filter((p) => p.rule_id === RULE_ID);
    console.log(`Filtered to rule ${RULE_ID}: ${proposals.length} match`);
  } else if (ALL) {
    // process all
  } else if (LIMIT > 0) {
    proposals = proposals.slice(0, LIMIT);
    console.log(`Limited to first ${LIMIT}`);
  } else {
    console.error('ERROR: must specify --all, --limit N, or --rule-id <ID>');
    process.exit(1);
  }

  let applied = 0;
  let skipped = 0;
  let notFound = 0;
  let parseFailed = 0;

  for (let i = 0; i < proposals.length; i++) {
    const p = proposals[i];
    const result = applyProposal(p);
    process.stdout.write(`  [${i + 1}/${proposals.length}] ${p.rule_id}... `);
    switch (result.status) {
      case 'applied':
        applied++;
        console.log(DRY_RUN ? 'WOULD-APPLY' : 'APPLIED');
        if (DRY_RUN && i < 3 && result.diff) {
          console.log(result.diff);
        }
        break;
      case 'skipped-existing':
        skipped++;
        console.log('SKIP (already has nist_ai_rmf)');
        break;
      case 'rule-not-found':
        notFound++;
        console.log('FAIL (rule file not found)');
        break;
      case 'parse-failed':
        parseFailed++;
        console.log('FAIL (patched YAML invalid)');
        break;
    }
  }

  console.log(`\n──────────────────────────────────────────────`);
  console.log(`Applied:        ${applied}`);
  console.log(`Skipped (existing): ${skipped}`);
  console.log(`Rule not found: ${notFound}`);
  console.log(`Parse failed:   ${parseFailed}`);
  console.log(`Total:          ${proposals.length}`);

  if (DRY_RUN) {
    console.log(`\nDry-run only. Run without --dry-run to write changes.`);
  } else if (applied > 0) {
    console.log(`\nNext steps:`);
    console.log(`  1. cd ${REPO_ROOT}`);
    console.log(`  2. git status (verify ${applied} files changed)`);
    console.log(`  3. git diff rules/ (spot-check 2-3 files)`);
    console.log(`  4. git checkout -b feat/nist-ai-rmf-mapping-v0.2`);
    console.log(`  5. git add rules/ && git commit -m "feat(compliance): expand NIST AI RMF mapping to 100% (v0.2)"`);
    console.log(`  6. gh pr create --base main --title "feat(compliance): NIST AI RMF mapping v0.2 (100% coverage)"`);
  }
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
