#!/usr/bin/env npx tsx
/**
 * scripts/measurement/backfill-from-report.ts
 *
 * One-off utility: read an existing eval report (in any of the legacy formats
 * we have on disk) and write the equivalent Measurement file under
 * `data/measurements/<source>/`.
 *
 * This bridges the migration: we have ~6 legacy report formats from before the
 * Measurement schema existed. Backfilling lets us preserve historical recall
 * numbers as immutable measurement files without re-running the evals.
 *
 * Usage:
 *   npx tsx scripts/measurement/backfill-from-report.ts <preset>
 *
 * Presets (one per legacy report shape):
 *   pint            data/pint-benchmark/pint-eval-report.json
 *   skill-benchmark data/skill-benchmark/benchmark-report.json
 *   hackaprompt     data/hackaprompt/hackaprompt-eval-report.json
 *   garak           data/garak-benchmark/garak-eval-report.json
 *   atr-self-test   data/eval-report.json
 *   wild-scan       data/mega-scan-report.json
 *   autoresearch    data/autoresearch/gap-report.json
 *
 * Each preset is intentionally small. We do not attempt a general legacy
 * report parser — the formats differ too much. A preset per shape is the
 * honest path.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { writeMeasurement, type MeasurementInput } from "../../src/measurement/write.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..");

interface Preset {
  reportPath: string;
  toMeasurement(raw: unknown): MeasurementInput;
}

function readJson(rel: string): unknown {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, rel), "utf-8"));
}

function safeNumber(v: unknown, fallback: number = 0): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback;
}

/**
 * eval-harness shape (used by atr-self-test, pint, hackaprompt):
 *   { report: { timestamp, corpusSize, overall: {recall, precision, f1, fpRate, confusion: {tp,fp,tn,fn}, sampleCount}, latency: {...}, byCategory: [...] } }
 */
function evalHarnessToMeasurement(
  raw: unknown,
  opts: { source: string; source_version: string; source_url?: string; notes?: string },
): MeasurementInput {
  const r = (raw as { report?: Record<string, unknown> }).report;
  if (!r) throw new Error("expected `report` top-level key");
  const overall = r.overall as Record<string, unknown> | undefined;
  if (!overall) throw new Error("expected `report.overall`");
  const confusion = overall.confusion as Record<string, unknown> | undefined;
  const latency = r.latency as Record<string, unknown> | undefined;
  const corpusSize = safeNumber(r.corpusSize);

  const m: MeasurementInput = {
    source: opts.source,
    source_version: opts.source_version,
    measured_at: typeof r.timestamp === "string" ? r.timestamp : undefined,
    samples: corpusSize,
    metrics: {
      recall: safeNumber(overall.recall),
      precision: safeNumber(overall.precision),
      f1: safeNumber(overall.f1),
      fp_rate: safeNumber(overall.fpRate ?? overall.fp_rate),
    },
    notes: opts.notes,
  };
  if (opts.source_url) m.source_url = opts.source_url;
  if (confusion) {
    m.confusion = {
      tp: safeNumber(confusion.tp),
      fp: safeNumber(confusion.fp),
      tn: safeNumber(confusion.tn),
      fn: safeNumber(confusion.fn),
    };
  }
  if (latency) {
    m.latency_ms = {
      p50: safeNumber(latency.p50),
      p95: safeNumber(latency.p95),
      p99: safeNumber(latency.p99),
      mean: safeNumber(latency.mean),
      max: safeNumber(latency.max),
    };
  }
  if (r.byCategory) m.breakdown = { by_category: r.byCategory };
  return m;
}

const PRESETS: Record<string, Preset> = {
  pint: {
    reportPath: "data/pint-benchmark/pint-eval-report.json",
    toMeasurement(raw) {
      return evalHarnessToMeasurement(raw, {
        source: "pint",
        source_version: "v1",
        source_url: "https://github.com/lakeraai/pint-benchmark",
        notes: "Invariant Labs PINT benchmark. 850-sample adversarial corpus.",
      });
    },
  },
  hackaprompt: {
    reportPath: "data/hackaprompt/hackaprompt-eval-report.json",
    toMeasurement(raw) {
      return evalHarnessToMeasurement(raw, {
        source: "hackaprompt",
        source_version: "v1",
        source_url: "https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset",
        notes: "HackAPrompt competition dataset. Real-world jailbreak attempts.",
      });
    },
  },
  "atr-self-test": {
    reportPath: "data/eval-report.json",
    toMeasurement(raw) {
      return evalHarnessToMeasurement(raw, {
        source: "atr-self-test",
        source_version: "internal",
        notes: "Engine regression eval against the union of all rules' own test_cases.",
      });
    },
  },

  /**
   * skill-benchmark shape (flat):
   *   { timestamp, corpus_size, malicious_count, benign_count, overall_recall, overall_precision, overall_f1, fp_rate, true_positives, false_positives, true_negatives, false_negatives, layer_a/b/c: {total, detected, recall} }
   */
  "skill-benchmark": {
    reportPath: "data/skill-benchmark/benchmark-report.json",
    toMeasurement(raw) {
      const r = raw as Record<string, unknown>;
      const layer_a = r.layer_a as Record<string, unknown> | undefined;
      const layer_b = r.layer_b as Record<string, unknown> | undefined;
      const layer_c = r.layer_c as Record<string, unknown> | undefined;
      return {
        source: "skill-benchmark",
        source_version: "internal-498",
        measured_at: typeof r.timestamp === "string" ? r.timestamp : undefined,
        samples: safeNumber(r.corpus_size),
        metrics: {
          recall: safeNumber(r.overall_recall),
          precision: safeNumber(r.overall_precision),
          f1: safeNumber(r.overall_f1),
          fp_rate: safeNumber(r.fp_rate),
        },
        confusion: {
          tp: safeNumber(r.true_positives),
          fp: safeNumber(r.false_positives),
          tn: safeNumber(r.true_negatives),
          fn: safeNumber(r.false_negatives),
        },
        breakdown: {
          layers: {
            a: layer_a ?? null,
            b: layer_b ?? null,
            c: layer_c ?? null,
          },
          malicious_count: safeNumber(r.malicious_count),
          benign_count: safeNumber(r.benign_count),
        },
        notes:
          "Internal 498-sample SKILL.md benchmark. Three layers: A=obvious payload, B=obfuscated, C=semantic.",
      };
    },
  },

  /**
   * garak shape (bespoke 2026-04-21 report):
   *   { benchmark, source, date, atr_version, rules_loaded, dataset: {total_prompts, type}, results: {detected, missed, recall} }
   */
  garak: {
    reportPath: "data/garak-benchmark/garak-eval-report.json",
    toMeasurement(raw) {
      const r = raw as Record<string, unknown>;
      const dataset = r.dataset as Record<string, unknown> | undefined;
      const results = r.results as Record<string, unknown> | undefined;
      const total = safeNumber(dataset?.total_prompts);
      const detected = safeNumber(results?.detected);
      const missed = safeNumber(results?.missed);
      const recallPct = safeNumber(results?.recall);
      const recall = recallPct > 1 ? recallPct / 100 : recallPct; // legacy report stored as 97.1
      const precision = detected > 0 ? 1 : 0; // dataset is 100% malicious; any detection is a true positive
      const f1 = recall + precision === 0 ? 0 : (2 * precision * recall) / (precision + recall);
      return {
        source: "garak",
        source_version: "in-the-wild-jailbreak-llms-2026-04",
        source_url: "https://github.com/NVIDIA/garak",
        measured_at: typeof r.date === "string" ? `${r.date}T00:00:00Z` : undefined,
        atr_version: typeof r.atr_version === "string" ? r.atr_version : undefined,
        rules_loaded: typeof r.rules_loaded === "number" ? r.rules_loaded : undefined,
        samples: total,
        metrics: {
          recall,
          precision,
          f1,
          fp_rate: 0, // 100% malicious corpus — FP rate is undefined; record 0 with notes
        },
        confusion: {
          tp: detected,
          fp: 0,
          tn: 0,
          fn: missed,
        },
        breakdown: {
          by_severity: r.by_severity ?? null,
          top_rules: r.top_rules ?? null,
        },
        notes:
          "NVIDIA garak inthewild_jailbreak_llms dataset. 100% malicious — FP rate is undefined on this corpus, recorded as 0. Recall is the load-bearing metric here.",
      };
    },
  },

  /**
   * mega-scan-report.json: wild-scan ecosystem flag-rate, not a recall benchmark.
   * No FN ground truth, so recall is undefined; we record flag-rate as recall=NaN→0 with notes.
   */
  "wild-scan": {
    reportPath: "data/mega-scan-report.json",
    toMeasurement(raw) {
      const r = raw as Record<string, unknown>;
      const totals = r.totals as Record<string, unknown> | undefined;
      const malware = r.malware_campaign as Record<string, unknown> | undefined;
      const scanned = safeNumber(totals?.scanned);
      const flagged = safeNumber(totals?.flagged);
      const confirmedMalware = safeNumber(malware?.confirmed_malware);
      // Use confirmed_malware as a precision-floor proxy: of the flagged, at least
      // 751 were confirmed malicious. We can't compute true recall without
      // ground-truth labels on the full corpus.
      const precisionFloor = flagged > 0 ? confirmedMalware / flagged : 0;
      return {
        source: "wild-scan",
        source_version: typeof r.scan_date === "string" ? `corpus-${r.scan_date.slice(0, 10)}` : "unknown",
        measured_at: typeof r.scan_date === "string" ? r.scan_date : undefined,
        atr_version: typeof r.engine_version === "string" ? r.engine_version : undefined,
        rules_loaded: typeof r.rules_loaded === "number" ? r.rules_loaded : undefined,
        samples: scanned,
        metrics: {
          recall: 0, // undefined on unlabeled corpus
          precision: precisionFloor,
          f1: 0,
          fp_rate: 0, // also undefined without labels
        },
        breakdown: {
          totals: r.totals ?? null,
          sources: r.sources ?? null,
          severity: r.severity ?? null,
          malware_campaign: r.malware_campaign ?? null,
          flagged_rate: r.flagged_rate ?? null,
        },
        notes:
          "Ecosystem wild scan, not a recall benchmark. The corpus has no ground-truth labels; `precision` is computed as confirmed_malware / flagged (precision floor). `recall` and `fp_rate` are undefined here and recorded as 0 by convention. Cite the flag rate from `breakdown.flagged_rate` for ecosystem context.",
      };
    },
  },

  autoresearch: {
    reportPath: "data/autoresearch/gap-report.json",
    toMeasurement(raw) {
      const r = raw as Record<string, unknown>;
      const summary = r.summary as Record<string, unknown> | undefined;
      const total = safeNumber(summary?.total);
      const detected = safeNumber(summary?.detected);
      const missed = safeNumber(summary?.missed);
      const recall = safeNumber(summary?.detection_rate);
      return {
        source: "autoresearch",
        source_version: "internal-1054",
        samples: total,
        metrics: {
          recall,
          precision: 1, // 100% adversarial input by construction; any detection is a TP
          f1: recall === 0 ? 0 : (2 * recall) / (recall + 1),
          fp_rate: 0,
        },
        confusion: {
          tp: detected,
          fp: 0,
          tn: 0,
          fn: missed,
        },
        breakdown: { clusters: r.clusters ?? null },
        notes:
          "Internal autoresearch adversarial corpus (1,054 samples). 100% adversarial — fp_rate undefined.",
      };
    },
  },
};

function main(): number {
  const preset = process.argv[2];
  if (!preset || !(preset in PRESETS)) {
    console.error("Usage: backfill-from-report.ts <preset>");
    console.error(`Presets: ${Object.keys(PRESETS).join(", ")}`);
    return 1;
  }
  const p = PRESETS[preset];
  let raw: unknown;
  try {
    raw = readJson(p.reportPath);
  } catch (err) {
    console.error(`Failed to read ${p.reportPath}: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  let input: MeasurementInput;
  try {
    input = p.toMeasurement(raw);
  } catch (err) {
    console.error(`Failed to convert ${p.reportPath}: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  const { measurementPath, latestPath } = writeMeasurement(input, { force: true });
  console.error(`wrote ${measurementPath}`);
  console.error(`updated ${latestPath}`);
  return 0;
}

process.exit(main());
