#!/usr/bin/env tsx
/**
 * ATR → Pipelock rules bundle compiler.
 *
 * Compiles regex-pattern ATR rules to Pipelock's rule bundle format
 * (format_version: 2). Builds the bundle file + fixture files; signing
 * is a separate step (pipelock sign), documented in the bundle README.
 *
 * Target format reference:
 *   https://github.com/luckyPipewrench/pipelock-rules
 *
 * Usage:
 *   npx tsx scripts/compile-pipelock.ts                    # default: rules/ -> dist/pipelock/atr-community/
 *   npx tsx scripts/compile-pipelock.ts --out dist/pipelock/atr-community
 *   npx tsx scripts/compile-pipelock.ts --bundle-name atr-community --tier community
 *
 * Output layout (matches pipelock-rules):
 *   dist/pipelock/<bundle-name>/
 *     bundle.yaml                                # the compiled bundle
 *     fixtures/<bundle-name>/<type>/<rule>.tp.txt  # true-positive fixtures
 *     fixtures/<bundle-name>/<type>/<rule>.fp.txt  # false-positive fixtures
 *     README.md                                  # signing + install instructions
 *
 * Capability declaration: atr/compiler/pipelock@1.0
 *
 * Scope: this compiler ships only the regex-pattern subset of ATR. Rules
 * with detection.method in {signature, semantic, behavioral, trace} are
 * skipped silently (pipelock is regex-only via Go RE2).
 */

import {
  readFileSync,
  writeFileSync,
  readdirSync,
  statSync,
  mkdirSync,
  rmSync,
  existsSync,
} from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import yaml from 'js-yaml';

const COMPILER_VERSION = '1.0.0';

// ---- Type definitions matching ATR + Pipelock ----

interface ATRRule {
  id: string;
  title: string;
  status: string;
  description?: string;
  severity: string;
  confidence?: string | number;
  maturity?: string;
  tags: { category: string; subcategory?: string };
  detection: {
    method?: string;
    conditions?: unknown;
    condition?: string;
  };
  references?: Record<string, unknown>;
  test_cases?: {
    true_positives?: Array<{ input?: string; description?: string }>;
    true_negatives?: Array<{ input?: string; description?: string }>;
  };
}

interface PipelockRule {
  id: string;
  type: 'dlp' | 'injection' | 'tool-poison';
  status: 'stable' | 'experimental';
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'high' | 'medium' | 'low';
  references: string[];
  tags: string[];
  pattern: { regex: string };
}

interface PipelockBundle {
  format_version: 2;
  name: string;
  version: string;
  tier: 'official' | 'community' | 'experimental';
  required_features: string[];
  monotonic_version: number;
  published_at: string;
  expires_at: string;
  min_pipelock: string;
  rules: PipelockRule[];
}

// ---- Category mapping ----

const ATR_TO_PIPELOCK_TYPE: Record<string, PipelockRule['type'] | null> = {
  'prompt-injection': 'injection',
  'context-exfiltration': 'dlp',
  'data-poisoning': 'dlp',
  'tool-poisoning': 'tool-poison',
  'skill-compromise': 'tool-poison',
  'privilege-escalation': null, // no direct pipelock type
  'agent-manipulation': 'injection',
  'excessive-autonomy': null,
  'model-abuse': null,
  'model-security': null,
};

function mapSeverity(s: string): PipelockRule['severity'] {
  const norm = String(s).toLowerCase();
  if (norm === 'critical' || norm === 'high' || norm === 'medium' || norm === 'low') {
    return norm as PipelockRule['severity'];
  }
  return 'medium';
}

function mapConfidence(c: string | number | undefined): PipelockRule['confidence'] {
  if (typeof c === 'number') {
    if (c >= 80) return 'high';
    if (c >= 50) return 'medium';
    return 'low';
  }
  const norm = String(c ?? '').toLowerCase();
  if (norm === 'high' || norm === 'medium' || norm === 'low') {
    return norm as PipelockRule['confidence'];
  }
  return 'medium';
}

function mapStatus(rule: ATRRule): PipelockRule['status'] {
  const m = (rule.maturity ?? '').toLowerCase();
  if (m === 'stable' || m === 'production') return 'stable';
  return 'experimental';
}

function extractRegex(rule: ATRRule): string | null {
  // Only regex-pattern rules can be mapped. Skip signature/semantic/trace/behavioral.
  const method = rule.detection?.method;
  if (method && method !== 'pattern') return null;

  const conditions = rule.detection?.conditions;
  if (!Array.isArray(conditions) || conditions.length === 0) return null;

  // Collect all regex patterns and join with |
  const patterns: string[] = [];
  for (const cond of conditions as Array<{ operator?: string; value?: string }>) {
    if (cond.operator === 'regex' && typeof cond.value === 'string') {
      // Pipelock requires RE2-compatible regex. We do NOT translate; if a
      // pattern uses look-around (?=, ?!) or backrefs (\1) it won't work in
      // Go RE2. Caller can run `pipelock validate` to catch that case.
      patterns.push(`(${cond.value})`);
    }
  }
  if (patterns.length === 0) return null;
  return patterns.join('|');
}

function collectReferences(rule: ATRRule): string[] {
  const refs: string[] = [];
  const r = rule.references ?? {};
  for (const key of ['cve', 'mitre_atlas', 'mitre_attack', 'owasp_llm', 'owasp_agentic']) {
    const arr = (r as Record<string, unknown>)[key];
    if (Array.isArray(arr)) {
      for (const item of arr) {
        if (typeof item === 'string') refs.push(`${key}:${item}`);
      }
    }
  }
  refs.push(`atr:${rule.id}`);
  return refs;
}

function collectTags(rule: ATRRule): string[] {
  const tags: string[] = [`atr-category:${rule.tags.category}`];
  if (rule.tags.subcategory) tags.push(`atr-subcategory:${rule.tags.subcategory}`);
  return tags;
}

// ---- Bundle compilation ----

interface CompileOptions {
  rulesDir: string;
  outDir: string;
  bundleName: string;
  tier: PipelockBundle['tier'];
  minPipelock: string;
  expiresInDays: number;
}

interface CompileStats {
  compiled: number;
  skipped: { atr_id: string; reason: string }[];
}

export function compileToPipelock(opts: CompileOptions): CompileStats {
  const stats: CompileStats = { compiled: 0, skipped: [] };
  const ruleFiles = findRuleFiles(opts.rulesDir);

  // Bundle path: dist/pipelock/<bundle>/bundle.yaml
  const bundleDir = join(opts.outDir);
  const fixturesRoot = join(bundleDir, 'fixtures', opts.bundleName);
  if (!existsSync(bundleDir)) mkdirSync(bundleDir, { recursive: true });

  const compiledRules: PipelockRule[] = [];

  for (const file of ruleFiles) {
    let rule: ATRRule;
    try {
      rule = yaml.load(readFileSync(file, 'utf8')) as ATRRule;
    } catch {
      stats.skipped.push({ atr_id: basename(file), reason: 'yaml-parse-failure' });
      continue;
    }
    if (!rule || typeof rule !== 'object' || !rule.id) {
      stats.skipped.push({ atr_id: basename(file), reason: 'no-id' });
      continue;
    }
    if (rule.status === 'deprecated') {
      stats.skipped.push({ atr_id: rule.id, reason: 'deprecated' });
      continue;
    }

    const pipelockType = ATR_TO_PIPELOCK_TYPE[rule.tags?.category];
    if (!pipelockType) {
      stats.skipped.push({ atr_id: rule.id, reason: `category-not-mappable:${rule.tags?.category}` });
      continue;
    }

    const regex = extractRegex(rule);
    if (!regex) {
      stats.skipped.push({ atr_id: rule.id, reason: 'non-regex-method-or-empty-conditions' });
      continue;
    }

    const compiled: PipelockRule = {
      id: rule.id,
      type: pipelockType,
      status: mapStatus(rule),
      name: rule.title,
      description: (rule.description ?? '').split('\n')[0].slice(0, 300),
      severity: mapSeverity(rule.severity),
      confidence: mapConfidence(rule.confidence),
      references: collectReferences(rule),
      tags: collectTags(rule),
      pattern: { regex },
    };
    compiledRules.push(compiled);
    stats.compiled++;

    // Emit fixture files: fixtures/<bundle>/<type>/<id>.tp.txt + .fp.txt
    const fxDir = join(fixturesRoot, pipelockType);
    if (!existsSync(fxDir)) mkdirSync(fxDir, { recursive: true });

    const tpLines = (rule.test_cases?.true_positives ?? [])
      .map((tc) => (typeof tc.input === 'string' ? tc.input : null))
      .filter((s): s is string => s !== null);
    const fpLines = (rule.test_cases?.true_negatives ?? [])
      .map((tc) => (typeof tc.input === 'string' ? tc.input : null))
      .filter((s): s is string => s !== null);

    if (tpLines.length > 0) {
      writeFileSync(join(fxDir, `${rule.id}.tp.txt`), tpLines.join('\n') + '\n');
    }
    if (fpLines.length > 0) {
      writeFileSync(join(fxDir, `${rule.id}.fp.txt`), fpLines.join('\n') + '\n');
    }
  }

  // Bundle header: CalVer YYYY.MM.<patch> derived from today + bundle.yaml content
  const now = new Date();
  const yyyymm = `${now.getUTCFullYear()}.${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
  const version = `${yyyymm}.${stats.compiled}`;
  const expires = new Date(now.getTime() + opts.expiresInDays * 86400000);

  const bundle: PipelockBundle = {
    format_version: 2,
    name: opts.bundleName,
    version,
    tier: opts.tier,
    required_features: ['regex'],
    monotonic_version: Math.floor(now.getTime() / 1000),
    published_at: now.toISOString(),
    expires_at: expires.toISOString(),
    min_pipelock: opts.minPipelock,
    rules: compiledRules,
  };

  writeFileSync(
    join(bundleDir, 'bundle.yaml'),
    `# Generated by atr-to-pipelock@${COMPILER_VERSION} on ${now.toISOString()}\n` +
      `# Source: https://github.com/Agent-Threat-Rule/agent-threat-rules\n` +
      `# Sign with: pipelock sign bundle.yaml --agent ${opts.bundleName}\n\n` +
      yaml.dump(bundle, { lineWidth: 200, noRefs: true }),
  );

  writeFileSync(
    join(bundleDir, 'README.md'),
    `# ATR-community Pipelock bundle

Compiled by \`scripts/compile-pipelock.ts\` from the [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) corpus.

- **${stats.compiled}** rules compiled from the regex-pattern subset.
- **${stats.skipped.length}** rules skipped (non-regex methods, non-mappable categories, deprecated rules).

## Sign and publish

\`\`\`bash
# Generate keypair once
pipelock keygen ${opts.bundleName}

# Sign the bundle
cd dist/pipelock/${opts.bundleName}
pipelock sign bundle.yaml --agent ${opts.bundleName}

# Publish bundle.yaml + bundle.yaml.sig + public key
# (location is operator's choice; agentthreatrule.org/pipelock/ is recommended)
\`\`\`

## End-user install

\`\`\`bash
pipelock rules install --source https://agentthreatrule.org/pipelock/bundle.yaml ${opts.bundleName}
# After confirming the public key fingerprint in the prompt
\`\`\`

## Trust model

This is a third-party bundle. End-users must add the ATR public key to
their \`pipelock.yaml\` \`trusted_keys\` before pipelock will load it.
Per pipelock's documented model (https://github.com/luckyPipewrench/pipelock/blob/main/docs/rules.md)
this is the supported path for community-maintained rule sources.

## Scope

This compiler ships ONLY the regex-pattern subset of ATR. ATR rules
using detection.method in {signature, semantic, behavioral, trace} are
not portable to pipelock's Go RE2 engine and are skipped.
`,
  );

  return stats;
}

// ---- File discovery ----

function findRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...findRuleFiles(p));
    else if (s.isFile() && (extname(entry) === '.yaml' || extname(entry) === '.yml')) {
      out.push(p);
    }
  }
  return out;
}

// ---- CLI ----

interface CliOptions {
  rulesDir: string;
  outDir: string;
  bundleName: string;
  tier: PipelockBundle['tier'];
  minPipelock: string;
  expiresInDays: number;
  verbose: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    rulesDir: 'rules',
    outDir: 'dist/pipelock/atr-community',
    bundleName: 'atr-community',
    tier: 'community',
    minPipelock: '2.5.0',
    expiresInDays: 365,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--rules') opts.rulesDir = argv[++i];
    else if (a === '--out') opts.outDir = argv[++i];
    else if (a === '--bundle-name') opts.bundleName = argv[++i];
    else if (a === '--tier') opts.tier = argv[++i] as PipelockBundle['tier'];
    else if (a === '--min-pipelock') opts.minPipelock = argv[++i];
    else if (a === '--expires-in-days') opts.expiresInDays = Number(argv[++i]);
    else if (a === '--verbose' || a === '-v') opts.verbose = true;
  }
  return opts;
}

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    console.error(`atr-to-pipelock compiler v${COMPILER_VERSION}

Usage:
  npx tsx scripts/compile-pipelock.ts [--rules rules/] [--out dist/pipelock/atr-community]
                                       [--bundle-name atr-community] [--tier community]
                                       [--min-pipelock 2.5.0] [--expires-in-days 365] [-v]

Capability declaration: atr/compiler/pipelock@${COMPILER_VERSION}`);
    process.exit(0);
  }

  const opts = parseArgs(argv);

  if (existsSync(opts.outDir)) {
    rmSync(opts.outDir, { recursive: true, force: true });
  }

  const stats = compileToPipelock(opts);

  console.error(`[atr-to-pipelock] compiled ${stats.compiled} rule(s) into ${opts.outDir}/bundle.yaml`);
  console.error(`[atr-to-pipelock] skipped ${stats.skipped.length} rule(s)`);
  if (opts.verbose) {
    const byReason: Record<string, number> = {};
    for (const s of stats.skipped) byReason[s.reason] = (byReason[s.reason] ?? 0) + 1;
    for (const [reason, count] of Object.entries(byReason).sort((a, b) => b[1] - a[1])) {
      console.error(`  ${reason}: ${count}`);
    }
  }
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) main();
