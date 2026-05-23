#!/usr/bin/env npx tsx
/**
 * eval-std-corpora.ts
 *
 * Runs ATR engine recall evaluation against three academic/standards corpora:
 *   1. Anthropic HH-RLHF red-team-attempts (5,000 sampled)
 *   2. OWASP LLM Top 10 attack scenarios (manually extracted)
 *   3. MITRE ATLAS LLM-relevant case study procedures (extracted)
 *
 * Output:
 *   - data/test-corpora/<source>/recall-results.json
 *   - data/test-corpora/combined-miss-clusters.json
 *
 * Usage:
 *   npx tsx scripts/eval-std-corpora.ts
 */

import { existsSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import yaml from 'js-yaml';
import { writeMeasurement } from '../src/measurement/write.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const CORPORA_DIR = resolve(REPO_ROOT, 'data/test-corpora');

// ─── Types ──────────────────────────────────────────────────────────────────

interface SampleEntry {
  id: string;
  text: string;
  source: string;
  attack_family?: string;
  metadata?: Record<string, unknown>;
}

interface EvalResult {
  id: string;
  text: string;
  source: string;
  attack_family?: string;
  matched: boolean;
  matched_rules: string[];
}

// ─── Rule loading ────────────────────────────────────────────────────────────

interface ATRCondition {
  field?: string;
  operator?: string;
  value?: string;
  description?: string;
}

interface LoadedRule {
  id: string;
  title: string;
  category: string;
  conditions: ATRCondition[];
}

function loadAllRules(): LoadedRule[] {
  const rules: LoadedRule[] = [];

  function walkDir(dir: string) {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        walkDir(fullPath);
      } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
        try {
          const content = readFileSync(fullPath, 'utf-8');
          const rule = yaml.load(content) as Record<string, unknown>;
          if (!rule || !rule.id || !rule.detection) continue;

          const detection = rule.detection as Record<string, unknown>;
          const conditions = detection.conditions as unknown[];
          if (!Array.isArray(conditions) || conditions.length === 0) continue;

          // Only keep pattern conditions with regex operators
          const patternConds: ATRCondition[] = [];
          for (const c of conditions) {
            const cond = c as Record<string, unknown>;
            if (cond.operator === 'regex' && cond.value && typeof cond.value === 'string') {
              patternConds.push({
                field: (cond.field as string) || 'content',
                operator: 'regex',
                value: cond.value as string,
                description: (cond.description as string) || ''
              });
            }
          }

          if (patternConds.length > 0) {
            rules.push({
              id: rule.id as string,
              title: (rule.title as string) || '',
              category: String((rule.tags as Record<string, unknown>)?.category || 'unknown'),
              conditions: patternConds
            });
          }
        } catch {
          // skip invalid files
        }
      }
    }
  }

  walkDir(RULES_DIR);
  return rules;
}

// ─── Pattern matching ────────────────────────────────────────────────────────

function evalText(text: string, rules: LoadedRule[]): string[] {
  const matched: string[] = [];
  for (const rule of rules) {
    for (const cond of rule.conditions) {
      try {
        const re = new RegExp(cond.value!, 'i');
        if (re.test(text)) {
          matched.push(rule.id);
          break; // count rule once
        }
      } catch {
        // invalid regex, skip
      }
    }
  }
  return matched;
}

// ─── HH-RLHF corpus loader ──────────────────────────────────────────────────

function loadHHRLHF(): SampleEntry[] {
  const path = join(CORPORA_DIR, 'hh-rlhf/sample-5000.json');
  if (!existsSync(path)) {
    console.error('HH-RLHF sample not found at', path);
    return [];
  }

  const raw = JSON.parse(readFileSync(path, 'utf-8')) as Array<{
    idx: number;
    first_human_turn: string;
    rating: number;
    task_description: string;
    tags: string;
  }>;

  return raw
    .filter(r => r.first_human_turn && r.first_human_turn.length > 10)
    .map(r => ({
      id: `hh-rlhf-${r.idx}`,
      text: r.first_human_turn,
      source: 'hh-rlhf',
      attack_family: categorizeHHRLHF(r.first_human_turn, r.task_description, r.tags),
      metadata: { rating: r.rating, task: r.task_description, tags: r.tags }
    }));
}

function categorizeHHRLHF(text: string, task: string, tags: string): string {
  const t = (text + ' ' + task + ' ' + tags).toLowerCase();
  if (/prompt.inject|jailbreak|ignore.{0,30}(instruction|rule|system|previous)|pretend.{0,30}(you are|to be)|act as if|roleplay.{0,30}(assistant|ai|model)/.test(t)) return 'prompt-injection';
  if (/steal|exfil|leak|extract.{0,20}(data|info|password|key|secret)|sensitive information/.test(t)) return 'data-exfiltration';
  if (/malware|virus|ransomware|trojan|exploit|hack|cyberat|ddos|sql.inject/.test(t)) return 'cyberattack';
  if (/weapon|bomb|explosive|poison|kill|murder|violence|harm/.test(t)) return 'physical-harm';
  if (/fraud|scam|phish|deceive|manipulat|social.engineer|impersonat/.test(t)) return 'social-engineering';
  if (/drug|illegal|synthesize|manufacture/.test(t)) return 'illegal-activity';
  if (/discriminat|hate|racist|sexist/.test(t)) return 'harmful-content';
  return 'other-harmful';
}

// ─── OWASP corpus loader ─────────────────────────────────────────────────────

function loadOWASP(): SampleEntry[] {
  const path = join(CORPORA_DIR, 'owasp-llm-top10/attack-scenarios.json');
  if (!existsSync(path)) {
    console.error('OWASP attack scenarios not found at', path);
    return [];
  }

  const raw = JSON.parse(readFileSync(path, 'utf-8')) as Array<{
    vuln_id: string;
    attack_scenarios: Array<{ section: string; text: string }>;
  }>;

  const entries: SampleEntry[] = [];
  for (const vuln of raw) {
    for (let i = 0; i < vuln.attack_scenarios.length; i++) {
      const scenario = vuln.attack_scenarios[i];
      const text = scenario.text.trim();
      if (text.length < 30) continue;

      entries.push({
        id: `owasp-${vuln.vuln_id}-${i}`,
        text,
        source: 'owasp-llm-top10',
        attack_family: owaspToFamily(vuln.vuln_id),
        metadata: { vuln_id: vuln.vuln_id, section: scenario.section }
      });
    }
  }
  return entries;
}

function owaspToFamily(vulnId: string): string {
  const map: Record<string, string> = {
    LLM01: 'prompt-injection',
    LLM02: 'sensitive-info-disclosure',
    LLM03: 'supply-chain',
    LLM04: 'data-model-poisoning',
    LLM05: 'improper-output-handling',
    LLM06: 'excessive-agency',
    LLM07: 'system-prompt-leakage',
    LLM08: 'vector-embedding-weakness',
    LLM09: 'misinformation',
    LLM10: 'unbounded-consumption'
  };
  return map[vulnId] || vulnId;
}

// ─── MITRE ATLAS corpus loader ──────────────────────────────────────────────

function loadATLAS(): SampleEntry[] {
  const path = join(CORPORA_DIR, 'mitre-atlas/attack-procedures.json');
  if (!existsSync(path)) {
    console.error('ATLAS attack procedures not found at', path);
    return [];
  }

  const raw = JSON.parse(readFileSync(path, 'utf-8')) as Array<{
    source_id: string;
    source_name: string;
    tactic: string;
    technique: string;
    attack_description: string;
    attack_family: string;
  }>;

  return raw
    .filter(r => r.attack_description && r.attack_description.length > 30)
    .map((r, i) => ({
      id: `atlas-${r.source_id}-${i}`,
      text: r.attack_description,
      source: 'mitre-atlas',
      attack_family: r.attack_family,
      metadata: {
        case_id: r.source_id,
        case_name: r.source_name,
        tactic: r.tactic,
        technique: r.technique
      }
    }));
}

// ─── Cluster misses ──────────────────────────────────────────────────────────

interface MissCluster {
  family: string;
  source: string;
  count: number;
  examples: string[];
  sample_ids: string[];
}

function clusterMisses(results: EvalResult[]): MissCluster[] {
  const misses = results.filter(r => !r.matched);

  // Group by source + family
  const groups = new Map<string, EvalResult[]>();
  for (const miss of misses) {
    const key = `${miss.source}::${miss.attack_family || 'unknown'}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(miss);
  }

  const clusters: MissCluster[] = [];
  for (const [key, items] of groups) {
    const [source, family] = key.split('::');
    clusters.push({
      family,
      source,
      count: items.length,
      examples: items.slice(0, 10).map(i => i.text.slice(0, 300)),
      sample_ids: items.slice(0, 10).map(i => i.id)
    });
  }

  // Sort by count desc
  return clusters.sort((a, b) => b.count - a.count);
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log('Loading ATR rules...');
  const rules = loadAllRules();
  console.log(`Loaded ${rules.length} rules with regex conditions`);

  // Load all three corpora
  console.log('\nLoading corpora...');
  const hhrlhf = loadHHRLHF();
  const owasp = loadOWASP();
  const atlas = loadATLAS();

  console.log(`  HH-RLHF: ${hhrlhf.length} samples`);
  console.log(`  OWASP LLM Top10: ${owasp.length} samples`);
  console.log(`  MITRE ATLAS: ${atlas.length} samples`);

  // Run eval on each corpus
  const allResults: EvalResult[] = [];

  for (const [corpus, samples] of [
    ['hh-rlhf', hhrlhf],
    ['owasp-llm-top10', owasp],
    ['mitre-atlas', atlas]
  ] as [string, SampleEntry[]][]) {
    console.log(`\nEvaluating ${corpus} (${samples.length} samples)...`);

    const results: EvalResult[] = [];
    let matched = 0;

    for (const sample of samples) {
      const matchedRules = evalText(sample.text, rules);
      const isMatched = matchedRules.length > 0;
      if (isMatched) matched++;

      results.push({
        id: sample.id,
        text: sample.text.slice(0, 500),
        source: sample.source,
        attack_family: sample.attack_family,
        matched: isMatched,
        matched_rules: matchedRules
      });
    }

    const recall = matched / samples.length;
    console.log(`  Matched: ${matched}/${samples.length} = ${(recall * 100).toFixed(1)}% recall`);

    // Family breakdown
    const byFamily = new Map<string, { total: number; matched: number }>();
    for (const r of results) {
      const fam = r.attack_family || 'unknown';
      if (!byFamily.has(fam)) byFamily.set(fam, { total: 0, matched: 0 });
      const entry = byFamily.get(fam)!;
      entry.total++;
      if (r.matched) entry.matched++;
    }

    console.log('  By family:');
    for (const [fam, stats] of [...byFamily.entries()].sort((a, b) => b[1].total - a[1].total)) {
      const famRecall = stats.matched / stats.total;
      console.log(`    ${fam}: ${stats.matched}/${stats.total} (${(famRecall * 100).toFixed(0)}% recall)`);
    }

    // Save legacy results
    const outPath = join(CORPORA_DIR, corpus, 'recall-results.json');
    writeFileSync(outPath, JSON.stringify(results, null, 2));
    console.log(`  Saved to ${outPath}`);

    // Standardized Measurement file (version-pinned, immutable).
    // 100% adversarial corpora → precision is 1 by construction; fp_rate undefined (0).
    const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);
    const byFamilyBreakdown: Record<string, { total: number; matched: number; recall: number }> = {};
    for (const [fam, stats] of byFamily.entries()) {
      byFamilyBreakdown[fam] = { total: stats.total, matched: stats.matched, recall: stats.matched / stats.total };
    }
    const { measurementPath } = writeMeasurement(
      {
        source: corpus,
        source_version: 'snapshot-2026-04',
        samples: samples.length,
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
          fn: samples.length - matched,
        },
        breakdown: { by_family: byFamilyBreakdown },
        notes: `${corpus} corpus — 100% adversarial samples; fp_rate undefined and recorded as 0 by convention.`,
      },
      { force: true },
    );
    console.log(`  Measurement: ${measurementPath}`);

    allResults.push(...results);
  }

  // Cluster misses
  console.log('\n\nClustering misses...');
  const clusters = clusterMisses(allResults);

  console.log('Top miss clusters (source::family, count):');
  for (const c of clusters.slice(0, 20)) {
    console.log(`  ${c.source}::${c.family}: ${c.count} misses`);
  }

  const clustersPath = join(CORPORA_DIR, 'combined-miss-clusters.json');
  writeFileSync(clustersPath, JSON.stringify(clusters, null, 2));
  console.log(`\nClusters saved to ${clustersPath}`);

  // Summary stats
  const totalHit = allResults.filter(r => r.matched).length;
  const totalMiss = allResults.filter(r => !r.matched).length;
  console.log(`\nOverall: ${totalHit} hit / ${totalMiss} miss / ${allResults.length} total`);
  console.log(`Combined recall: ${(totalHit / allResults.length * 100).toFixed(1)}%`);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
