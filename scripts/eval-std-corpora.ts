#!/usr/bin/env npx tsx
/**
 * eval-std-corpora.ts
 *
 * Runs ATR engine recall evaluation against three academic/standards corpora:
 *   1. Anthropic HH-RLHF red-team-attempts (5,000 sampled)
 *   2. OWASP LLM Top 10 attack scenarios (manually extracted)
 *   3. MITRE ATLAS LLM-relevant case study procedures (extracted)
 *
 * WHY THIS FILE WAS REWRITTEN (2026-08-05)
 *
 * Until this commit the script never ran the ATR engine. It walked `rules/`
 * with js-yaml, kept only `operator: regex` conditions, flattened every
 * condition of every rule into one implicit OR, and tested each pattern with a
 * hand-rolled `new RegExp(value, 'i')` against the raw sample string. That
 * shadow matcher differs from `src/engine.ts` on every axis that matters:
 *
 *   - NO STATUS GATE. `status: draft|deprecated` rules — which the engine skips
 *     outright, before the lane gate — were counted as detections.
 *   - NO LANE GATE. `maturity` was never read, so an experimental rule scored
 *     the same as a stable one.
 *   - NO FIELD RESOLUTION. `cond.field` was parsed and then discarded. A
 *     condition declared on `tool_response` or `file_path` was tested against
 *     the natural-language sample, which production would never do.
 *   - NO CONDITION LOGIC. `detection.condition: all` was ignored; every rule
 *     behaved as `any`, so a 4-of-4 AND rule fired on 1 of 4.
 *   - NO NON-REGEX OPERATORS, NO EXCLUSIONS, NO ReDoS GATE.
 *   - WRONG REGEX FLAGS. The engine picks `iu` when a pattern contains `\u{`
 *     (src/engine.ts:883); the shadow matcher always used `i`. Without the `u`
 *     flag `[\u{E0001}\u{E007F}]` is not a codepoint range — JS reads it as the
 *     literal class `[u{E0017F}]`, i.e. "contains any of u { E 0 1 } 7 F". That
 *     single condition of ATR-2026-00258 matched any English text containing
 *     the letter `e`, which is why all three corpora reported 99-100% recall.
 *     The number measured how many samples contain a vowel, not what ATR
 *     detects.
 *
 * Every sample now goes through the real `ATREngine` via the canonical shape
 * set in `scripts/lib/corpus-event.ts` — the same entry point the FP gates use,
 * so a rule can never earn detection credit on a presentation wider than the
 * one it pays its false positives on.
 *
 * ON PRECISION: these three corpora are 100% adversarial. They contain no
 * benign samples, so precision and fp_rate CANNOT be computed from them. The
 * measurement schema requires numbers, so the repo-wide convention (precision
 * 1, fp_rate 0) is preserved — but the `notes` field says out loud that these
 * are conventions, not measurements. Do not quote them.
 *
 * Output:
 *   - data/test-corpora/<source>/recall-results.json
 *   - data/test-corpora/combined-miss-clusters.json
 *   - data/measurements/<source>/<pinned>.json (+ latest.json)
 *
 * Usage:
 *   npx tsx scripts/eval-std-corpora.ts
 *   npx tsx scripts/eval-std-corpora.ts --lane enforce   # stable-only lane
 *   npx tsx scripts/eval-std-corpora.ts --no-write       # report only
 */

import { existsSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import yaml from 'js-yaml';
import { ATREngine } from '../src/engine.js';
import { writeMeasurement } from '../src/measurement/write.js';
import {
  matchedRuleIds,
  shapeNames,
  statusCoverage,
  fieldCoverage,
  type RuleLike,
} from './lib/corpus-event.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const CORPORA_DIR = resolve(REPO_ROOT, 'data/test-corpora');

type Lane = 'enforce' | 'alert' | 'hunt';

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

interface Args {
  lane: Lane;
  write: boolean;
}

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  const at = (flag: string): string | null => {
    const i = argv.indexOf(flag);
    return i >= 0 ? (argv[i + 1] ?? null) : null;
  };
  const laneArg = at('--lane');
  const lane: Lane =
    laneArg === 'enforce' || laneArg === 'alert' || laneArg === 'hunt' ? laneArg : 'hunt';
  if (laneArg !== null && laneArg !== lane) {
    throw new Error(`--lane must be one of enforce|alert|hunt (got ${JSON.stringify(laneArg)})`);
  }
  return { lane, write: !argv.includes('--no-write') };
}

// ─── Rule inventory (for honesty reporting only — NOT for matching) ──────────

/**
 * Parse rule front-matter to report what this harness structurally cannot
 * measure. Matching itself is done exclusively by ATREngine; this walk exists
 * so the run can state which rules the engine refuses to evaluate (inert
 * status) and which declare fields a text corpus cannot fill, instead of
 * silently folding them into the miss count.
 */
function loadRuleShells(): RuleLike[] {
  const shells: RuleLike[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.name.endsWith('.yaml') && !entry.name.endsWith('.yml')) continue;
      try {
        const rule = yaml.load(readFileSync(full, 'utf-8')) as Record<string, unknown> | null;
        if (!rule || typeof rule.id !== 'string') continue;
        shells.push(rule as unknown as RuleLike);
      } catch {
        // Unparseable file: the engine will not load it either. Nothing to report.
      }
    }
  };
  walk(RULES_DIR);
  return shells;
}

function reportCoverageGaps(shells: readonly RuleLike[]): void {
  const inert = statusCoverage(shells);
  const fields = fieldCoverage(shells);
  const zeroMeasurement = fields.filter((f) => f.zeroMeasurement);
  console.log(`  Rule files on disk: ${shells.length}`);
  console.log(
    `  Inert (status draft/deprecated — engine skips before the lane gate): ${inert.length}`,
  );
  const enforceClaiming = inert.filter((i) => i.claimsEnforceLane);
  if (enforceClaiming.length > 0) {
    console.log(
      `    of which claim the enforce lane: ${enforceClaiming.length} (${enforceClaiming
        .map((i) => i.ruleId)
        .join(', ')})`,
    );
  }
  console.log(
    `  Zero-measurement for a TEXT corpus (trace/behavioral/signature method, or an ` +
      `unfillable field under AND): ${zeroMeasurement.length}`,
  );
  console.log(
    `  These rules cannot contribute a detection here. Recall below is the engine's ` +
      `result over the rules it will actually evaluate — it is not evidence about the rest.`,
  );
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

// ─── Evaluation ──────────────────────────────────────────────────────────────

interface FamilyStat {
  total: number;
  matched: number;
}

/**
 * Run one corpus through the real engine. Every sample goes through
 * `matchedRuleIds` — the canonical shape set plus scanSkill() — so detections
 * here are counted on exactly the presentation the FP gates charge for.
 */
function evaluateCorpus(engine: ATREngine, samples: readonly SampleEntry[]): EvalResult[] {
  const results: EvalResult[] = [];
  for (const sample of samples) {
    const ids = [...matchedRuleIds(engine, sample.text)].sort();
    results.push({
      id: sample.id,
      text: sample.text.slice(0, 500),
      source: sample.source,
      attack_family: sample.attack_family,
      matched: ids.length > 0,
      matched_rules: ids,
    });
  }
  return results;
}

function familyBreakdown(results: readonly EvalResult[]): Map<string, FamilyStat> {
  const byFamily = new Map<string, FamilyStat>();
  for (const r of results) {
    const fam = r.attack_family || 'unknown';
    const entry = byFamily.get(fam) ?? { total: 0, matched: 0 };
    byFamily.set(fam, {
      total: entry.total + 1,
      matched: entry.matched + (r.matched ? 1 : 0),
    });
  }
  return byFamily;
}

/**
 * Rule ids that carried the corpus, most-load-bearing first. A corpus whose
 * recall rests on one rule is a corpus that measures that rule, not the ruleset
 * — the failure mode that produced the pre-2026-08-05 numbers.
 */
function topContributingRules(results: readonly EvalResult[], limit: number): [string, number][] {
  const counts = new Map<string, number>();
  for (const r of results) {
    for (const id of r.matched_rules) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function measurementNotes(corpus: string, lane: Lane, ruleCount: number): string {
  return (
    `${corpus} corpus — 100% adversarial samples. Measured by src/engine.ts (ATREngine, ` +
    `lane=${lane}, ${ruleCount} rules loaded) through the canonical event shapes in ` +
    `scripts/lib/corpus-event.ts (${shapeNames().join(', ')}) plus scanSkill(). ` +
    `PRECISION AND FP_RATE ARE NOT MEASURED: this corpus contains no benign samples, so ` +
    `there is no true-negative population to compute them from. The values 1 and 0 are the ` +
    `repo-wide schema convention for adversarial-only corpora, not results — do not quote ` +
    `them. For real precision see the benign-gate measurements. Supersedes all measurements ` +
    `of this source before 2026-08-05, which were produced by a shadow regex matcher in ` +
    `scripts/eval-std-corpora.ts and never ran the engine.`
  );
}

function reportCorpus(corpus: string, results: readonly EvalResult[], samples: number): void {
  const matched = results.filter((r) => r.matched).length;
  const recall = samples > 0 ? matched / samples : 0;
  console.log(`  Matched: ${matched}/${samples} = ${(recall * 100).toFixed(1)}% recall`);
  console.log('  By family:');
  const byFamily = familyBreakdown(results);
  for (const [fam, stats] of [...byFamily.entries()].sort((a, b) => b[1].total - a[1].total)) {
    const famRecall = stats.total > 0 ? stats.matched / stats.total : 0;
    console.log(`    ${fam}: ${stats.matched}/${stats.total} (${(famRecall * 100).toFixed(0)}% recall)`);
  }
  const top = topContributingRules(results, 8);
  if (top.length > 0) {
    console.log('  Rules carrying this corpus (id: samples matched):');
    for (const [id, n] of top) {
      console.log(`    ${id}: ${n} (${((n / samples) * 100).toFixed(1)}% of corpus)`);
    }
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs();

  console.log('Loading ATR engine...');
  const engine = new ATREngine({ rulesDir: RULES_DIR, lane: args.lane });
  const ruleCount = await engine.loadRules();
  console.log(`Loaded ${ruleCount} rules (lane=${args.lane})`);
  console.log(`Event shapes: ${shapeNames().join(', ')} + scanSkill()`);

  console.log('\nWhat this harness structurally cannot measure:');
  reportCoverageGaps(loadRuleShells());

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

    const results = evaluateCorpus(engine, samples);
    const matched = results.filter((r) => r.matched).length;
    const recall = samples.length > 0 ? matched / samples.length : 0;
    reportCorpus(corpus, results, samples.length);

    // Save legacy results
    const outPath = join(CORPORA_DIR, corpus, 'recall-results.json');
    if (args.write) {
      writeFileSync(outPath, JSON.stringify(results, null, 2));
      console.log(`  Saved to ${outPath}`);
    }

    // Standardized Measurement file (version-pinned, immutable).
    // Precision / fp_rate are conventions here, NOT measurements — see notes.
    const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);
    const byFamily = familyBreakdown(results);
    const byFamilyBreakdown: Record<string, { total: number; matched: number; recall: number }> = {};
    for (const [fam, stats] of byFamily.entries()) {
      byFamilyBreakdown[fam] = { total: stats.total, matched: stats.matched, recall: stats.matched / stats.total };
    }
    const topRules: Record<string, number> = {};
    for (const [id, n] of topContributingRules(results, 10)) topRules[id] = n;

    if (!args.write) {
      console.log('  --no-write: measurement not persisted');
      allResults.push(...results);
      continue;
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
        breakdown: { by_family: byFamilyBreakdown, top_contributing_rules: topRules, lane: args.lane },
        notes: measurementNotes(corpus, args.lane, ruleCount),
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

  if (args.write) {
    const clustersPath = join(CORPORA_DIR, 'combined-miss-clusters.json');
    writeFileSync(clustersPath, JSON.stringify(clusters, null, 2));
    console.log(`\nClusters saved to ${clustersPath}`);
  }

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
