import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Benchmark claims that go into the pack manifest.
 *
 * These are the only numbers the pack shows to the outside world, so they are
 * read from `data/measurements/<source>/latest.json` rather than typed in.
 * A missing or malformed measurement is a hard error: the pack must never
 * ship a number that no measurement file backs. That is exactly how the
 * previously shipped pack came to advertise a retired precision figure.
 */

export interface Measurement {
  readonly source: string;
  readonly atr_version: string;
  readonly samples: number;
  readonly measured_at: string;
  readonly metrics: {
    readonly recall?: number;
    readonly precision?: number;
    readonly fp_rate?: number;
  };
}

export interface BenchmarkClaims {
  readonly garak: Measurement;
  readonly skill: Measurement;
  readonly owaspAgenticCategories: number;
  /** Sentence embedded in pack.yaml `description`. */
  readonly sentence: string;
  /** Longer prose for README.md. */
  readonly readmeLine: string;
}

function readMeasurement(repoRoot: string, source: string): Measurement {
  const path = join(repoRoot, 'data', 'measurements', source, 'latest.json');
  if (!existsSync(path)) {
    throw new Error(
      `no measurement file for "${source}" at ${path} — refusing to emit a benchmark claim without one`,
    );
  }
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as Measurement;
  const recall = parsed.metrics?.recall;
  if (typeof recall !== 'number' || !Number.isFinite(recall)) {
    throw new Error(`measurement for "${source}" has no numeric metrics.recall`);
  }
  if (typeof parsed.atr_version !== 'string' || parsed.atr_version.length === 0) {
    throw new Error(`measurement for "${source}" has no atr_version — cannot pin the claim`);
  }
  return parsed;
}

function pct(value: number | undefined): string {
  if (typeof value !== 'number') throw new Error('missing metric');
  return `${(value * 100).toFixed(1)}%`;
}

export function loadBenchmarkClaims(repoRoot: string, owaspAgenticCategories: number): BenchmarkClaims {
  const garak = readMeasurement(repoRoot, 'garak');
  const skill = readMeasurement(repoRoot, 'skill-benchmark');
  const sentence =
    `Benchmarks (each pinned to the ATR version it was measured against, ` +
    `see the ATR repository's Evaluation section for the full table): ` +
    `${pct(garak.metrics.recall)} recall on the ${garak.samples.toLocaleString('en-US')}-sample ` +
    `NVIDIA garak in-the-wild jailbreak corpus (ATR ${garak.atr_version}); ` +
    `${pct(skill.metrics.recall)} recall and ${pct(skill.metrics.precision)} precision on ` +
    `${skill.samples} labeled SKILL.md samples (ATR ${skill.atr_version}), ` +
    `measured in the hunt lane, which is the lane this pack corresponds to. ` +
    `OWASP Agentic Top 10: ${owaspAgenticCategories}/10 categories mapped.`;
  const readmeLine =
    `${pct(garak.metrics.recall)} recall on NVIDIA garak ` +
    `(${garak.samples.toLocaleString('en-US')} in-the-wild jailbreaks, ATR ${garak.atr_version}) · ` +
    `${pct(skill.metrics.recall)} recall / ${pct(skill.metrics.precision)} precision on ` +
    `${skill.samples} labeled SKILL.md samples (ATR ${skill.atr_version}, hunt lane) · ` +
    `OWASP Agentic Top 10: ${owaspAgenticCategories}/10`;
  return { garak, skill, owaspAgenticCategories, sentence, readmeLine };
}
