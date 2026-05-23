/**
 * SKILL.md Benchmark Harness
 *
 * Evaluates the ATR scanSkill() method against a labeled corpus of
 * malicious and benign SKILL.md files. Produces per-layer recall,
 * overall precision, and a detailed per-sample report.
 *
 * Corpus: data/skill-benchmark/manifest.json
 * Samples: data/skill-benchmark/malicious/ and data/skill-benchmark/benign/
 *
 * Layers:
 *   A = obvious payload (curl|bash, base64 exec, reverse shell)
 *   B = obfuscated (bash expansion, paste service relay, encoded)
 *   C = semantic (natural language instructions, social engineering)
 *
 * @module agent-threat-rules/eval/skill-benchmark
 */

import { resolve, join } from 'node:path';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { ATREngine } from '../engine.js';
import { writeMeasurement } from '../measurement/write.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ManifestEntry {
  readonly file: string;
  readonly label: 'malicious' | 'benign';
  readonly attack_type: string;
  readonly source: string;
  readonly layer: 'A' | 'B' | 'C' | '';
}

interface ExpectedFinding {
  readonly rule_id: string;
  readonly category: string;
  readonly severity: string;
}

interface ExpectedEntry {
  readonly expected_safe: boolean;
  readonly expected_findings: readonly ExpectedFinding[];
  readonly detected: boolean;
}

interface SampleResult {
  readonly file: string;
  readonly label: 'malicious' | 'benign';
  readonly layer: string;
  readonly attack_type: string;
  readonly detected: boolean;
  readonly rules_fired: readonly string[];
  readonly correct: boolean;
  readonly latency_ms: number;
  readonly expected_rules_matched: boolean;
  readonly category_correct: boolean;
}

interface LayerMetrics {
  readonly total: number;
  readonly detected: number;
  readonly recall: number;
}

interface SkillBenchmarkReport {
  readonly timestamp: string;
  readonly corpus_size: number;
  readonly malicious_count: number;
  readonly benign_count: number;
  readonly overall_recall: number;
  readonly overall_precision: number;
  readonly overall_f1: number;
  readonly fp_rate: number;
  readonly layer_a: LayerMetrics;
  readonly layer_b: LayerMetrics;
  readonly layer_c: LayerMetrics;
  readonly true_positives: number;
  readonly false_positives: number;
  readonly true_negatives: number;
  readonly false_negatives: number;
  readonly expected_rules_accuracy: number;
  readonly category_accuracy: number;
  readonly avg_latency_ms: number;
  readonly max_latency_ms: number;
  readonly results: readonly SampleResult[];
  readonly missed_attacks: readonly SampleResult[];
  readonly false_alarms: readonly SampleResult[];
}

// ---------------------------------------------------------------------------
// Benchmark runner
// ---------------------------------------------------------------------------

export async function runSkillBenchmark(options?: {
  readonly rulesDir?: string;
  readonly corpusDir?: string;
  readonly outputPath?: string;
}): Promise<SkillBenchmarkReport> {
  const repoRoot = resolve(import.meta.dirname, '..', '..');
  const rulesDir = options?.rulesDir ?? join(repoRoot, 'rules');
  const corpusDir = options?.corpusDir ?? join(repoRoot, 'data', 'skill-benchmark');
  const outputPath = options?.outputPath ?? join(repoRoot, 'data', 'skill-benchmark', 'benchmark-report.json');

  // Load manifest
  const manifestPath = join(corpusDir, 'manifest.json');
  if (!existsSync(manifestPath)) {
    throw new Error(`Manifest not found: ${manifestPath}`);
  }
  const manifest: readonly ManifestEntry[] = JSON.parse(readFileSync(manifestPath, 'utf-8'));

  // Load expected findings (Cisco-style ground truth)
  const expectedPath = join(corpusDir, 'expected-findings.json');
  const expectedMap: Record<string, ExpectedEntry> = existsSync(expectedPath)
    ? JSON.parse(readFileSync(expectedPath, 'utf-8'))
    : {};

  // Load engine
  const engine = new ATREngine({ rulesDir });
  await engine.loadRules();

  // Run each sample
  const results: SampleResult[] = [];

  for (const entry of manifest) {
    const filePath = join(corpusDir, entry.file);
    if (!existsSync(filePath)) {
      console.error(`SKIP: file not found: ${entry.file}`);
      continue;
    }

    const content = readFileSync(filePath, 'utf-8');
    const start = performance.now();
    const matches = engine.scanSkill(content);
    const elapsed = performance.now() - start;

    const detected = matches.length > 0;
    const rulesFired = matches.map((m) => m.rule.id);

    const correct =
      (entry.label === 'malicious' && detected) ||
      (entry.label === 'benign' && !detected);

    // Validate expected findings (Cisco-style category + rule matching)
    const expected = expectedMap[entry.file];
    const expectedRulesMatched = expected?.expected_findings
      ? expected.expected_findings.every((ef) => rulesFired.includes(ef.rule_id))
      : true; // no expected = pass by default
    const expectedCategories = expected?.expected_findings?.map((ef) => ef.category) ?? [];
    const actualCategories = matches.map((m) => m.rule.tags.category);
    const categoryCorrect = expectedCategories.every((ec) =>
      actualCategories.includes(ec as typeof actualCategories[number]),
    );

    results.push({
      file: entry.file,
      label: entry.label,
      layer: entry.layer || '',
      attack_type: entry.attack_type,
      detected,
      rules_fired: rulesFired,
      correct,
      latency_ms: Math.round(elapsed * 100) / 100,
      expected_rules_matched: expectedRulesMatched,
      category_correct: categoryCorrect,
    });
  }

  // Compute metrics
  const malicious = results.filter((r) => r.label === 'malicious');
  const benign = results.filter((r) => r.label === 'benign');

  const tp = malicious.filter((r) => r.detected).length;
  const fn = malicious.filter((r) => !r.detected).length;
  const fp = benign.filter((r) => r.detected).length;
  const tn = benign.filter((r) => !r.detected).length;

  const recall = malicious.length > 0 ? tp / malicious.length : 0;
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const f1 = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
  const fpRate = benign.length > 0 ? fp / benign.length : 0;

  // Per-layer metrics
  const layerMetrics = (layer: string): LayerMetrics => {
    const samples = malicious.filter((r) => r.layer === layer);
    const detected = samples.filter((r) => r.detected).length;
    return {
      total: samples.length,
      detected,
      recall: samples.length > 0 ? detected / samples.length : 0,
    };
  };

  const latencies = results.map((r) => r.latency_ms);

  // Expected findings accuracy
  const detectedMalicious = malicious.filter((r) => r.detected);
  const expectedRulesAccuracy = detectedMalicious.length > 0
    ? detectedMalicious.filter((r) => r.expected_rules_matched).length / detectedMalicious.length
    : 0;
  const categoryAccuracy = detectedMalicious.length > 0
    ? detectedMalicious.filter((r) => r.category_correct).length / detectedMalicious.length
    : 0;

  const report: SkillBenchmarkReport = {
    timestamp: new Date().toISOString(),
    corpus_size: results.length,
    malicious_count: malicious.length,
    benign_count: benign.length,
    overall_recall: Math.round(recall * 1000) / 1000,
    overall_precision: Math.round(precision * 1000) / 1000,
    overall_f1: Math.round(f1 * 1000) / 1000,
    fp_rate: Math.round(fpRate * 1000) / 1000,
    layer_a: layerMetrics('A'),
    layer_b: layerMetrics('B'),
    layer_c: layerMetrics('C'),
    true_positives: tp,
    false_positives: fp,
    true_negatives: tn,
    false_negatives: fn,
    expected_rules_accuracy: Math.round(expectedRulesAccuracy * 1000) / 1000,
    category_accuracy: Math.round(categoryAccuracy * 1000) / 1000,
    avg_latency_ms: Math.round((latencies.reduce((a, b) => a + b, 0) / latencies.length) * 100) / 100,
    max_latency_ms: Math.round(Math.max(...latencies) * 100) / 100,
    results,
    missed_attacks: malicious.filter((r) => !r.detected),
    false_alarms: benign.filter((r) => r.detected),
  };

  // Save report
  writeFileSync(outputPath, JSON.stringify(report, null, 2));

  return report;
}

// ---------------------------------------------------------------------------
// Measurement adapter (CLI-only — tests call runSkillBenchmark and skip this)
// ---------------------------------------------------------------------------

/**
 * Write the standardized version-pinned Measurement file for a SkillBenchmark
 * report. Separated from runSkillBenchmark so unit tests can exercise the
 * benchmark logic without mutating data/measurements/ on disk (which would
 * make the CI 'sync-stats --check' drift gate flake).
 *
 * Called from the CLI block at the bottom of this file and from any
 * external script that wants to persist the measurement. Safe to call
 * repeatedly the same day — uses force=true.
 */
export function writeSkillBenchmarkMeasurement(report: SkillBenchmarkReport): void {
  writeMeasurement(
    {
      source: 'skill-benchmark',
      source_version: 'internal-498',
      measured_at: report.timestamp,
      samples: report.corpus_size,
      metrics: {
        recall: report.overall_recall,
        precision: report.overall_precision,
        f1: report.overall_f1,
        fp_rate: report.fp_rate,
      },
      confusion: {
        tp: report.true_positives,
        fp: report.false_positives,
        tn: report.true_negatives,
        fn: report.false_negatives,
      },
      latency_ms: {
        p50: report.avg_latency_ms,
        p95: report.max_latency_ms,
        p99: report.max_latency_ms,
        mean: report.avg_latency_ms,
        max: report.max_latency_ms,
      },
      breakdown: {
        layers: {
          a: report.layer_a,
          b: report.layer_b,
          c: report.layer_c,
        },
        malicious_count: report.malicious_count,
        benign_count: report.benign_count,
        expected_rules_accuracy: report.expected_rules_accuracy,
        category_accuracy: report.category_accuracy,
      },
      notes:
        'Internal 498-sample SKILL.md benchmark. Layer A = obvious payload, Layer B = obfuscated, Layer C = semantic.',
    },
    { force: true },
  );
}

// ---------------------------------------------------------------------------
// CLI runner
// ---------------------------------------------------------------------------

function formatPercent(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

export function printReport(report: SkillBenchmarkReport): void {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║       SKILL.md BENCHMARK REPORT                 ║');
  console.log('╚══════════════════════════════════════════════════╝\n');

  console.log(`Corpus: ${report.corpus_size} samples (${report.malicious_count} malicious, ${report.benign_count} benign)`);
  console.log(`Timestamp: ${report.timestamp}\n`);

  console.log('┌─────────────────┬──────────┐');
  console.log(`│ Overall Recall  │ ${formatPercent(report.overall_recall).padStart(8)} │`);
  console.log(`│ Overall Prec.   │ ${formatPercent(report.overall_precision).padStart(8)} │`);
  console.log(`│ F1 Score        │ ${formatPercent(report.overall_f1).padStart(8)} │`);
  console.log(`│ FP Rate         │ ${formatPercent(report.fp_rate).padStart(8)} │`);
  console.log('└─────────────────┴──────────┘\n');

  console.log('Per-Layer Recall:');
  console.log(`  Layer A (obvious):    ${formatPercent(report.layer_a.recall)} (${report.layer_a.detected}/${report.layer_a.total})`);
  console.log(`  Layer B (obfuscated): ${formatPercent(report.layer_b.recall)} (${report.layer_b.detected}/${report.layer_b.total})`);
  console.log(`  Layer C (semantic):   ${formatPercent(report.layer_c.recall)} (${report.layer_c.detected}/${report.layer_c.total})\n`);

  console.log('Finding Accuracy (Cisco-style):');
  console.log(`  Expected rules matched: ${formatPercent(report.expected_rules_accuracy)}`);
  console.log(`  Category accuracy:      ${formatPercent(report.category_accuracy)}\n`);

  console.log('Confusion Matrix:');
  console.log(`  TP: ${report.true_positives}  FP: ${report.false_positives}`);
  console.log(`  FN: ${report.false_negatives}  TN: ${report.true_negatives}\n`);

  console.log(`Latency: avg ${report.avg_latency_ms}ms, max ${report.max_latency_ms}ms\n`);

  if (report.missed_attacks.length > 0) {
    console.log('MISSED ATTACKS:');
    for (const m of report.missed_attacks) {
      console.log(`  ✗ [${m.layer}] ${m.file} (${m.attack_type})`);
    }
    console.log('');
  }

  if (report.false_alarms.length > 0) {
    console.log('FALSE POSITIVES:');
    for (const f of report.false_alarms) {
      console.log(`  ✗ ${f.file} → ${f.rules_fired.join(', ')}`);
    }
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// Direct execution
// ---------------------------------------------------------------------------

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('skill-benchmark.ts')) {
  runSkillBenchmark().then((report) => {
    printReport(report);
    console.log(`Report saved to: data/skill-benchmark/benchmark-report.json`);
    // Write the standardized version-pinned Measurement file. CLI-only —
    // unit tests call runSkillBenchmark() directly and skip this.
    writeSkillBenchmarkMeasurement(report);
    console.log(`Measurement: data/measurements/skill-benchmark/`);
  }).catch((err) => {
    console.error('Benchmark failed:', err);
    process.exit(1);
  });
}
