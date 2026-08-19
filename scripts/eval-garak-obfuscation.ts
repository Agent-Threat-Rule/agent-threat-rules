#!/usr/bin/env npx tsx
/**
 * eval-garak-obfuscation.ts — recall before vs after the real garak obfuscations.
 *
 * Reads the corpus built by scripts/garak-obfuscate.ts and reports, per
 * transform and per EVENT SHAPE:
 *
 *   - plaintext recall on the same seeds (the baseline the obfuscated number
 *     has to be read against),
 *   - obfuscated recall,
 *   - what ATR's normalization layer did to the sample: whether
 *     foldConfusables(normalizeUnicode(text)) reconstructs the plaintext seed
 *     (the transform is neutralised), merely changes the text, or leaves it
 *     untouched (the transform passes straight through).
 *
 * The normalization column is the point of the exercise. A transform that
 * normalization reverses needs no rule; a transform that survives normalization
 * AND drops recall is where a rule could earn its place.
 *
 * Usage:
 *   npx tsx scripts/eval-garak-obfuscation.ts [--corpus <path>] [--output <path>]
 *                                            [--cap <n>]
 *
 * --cap takes an evenly spaced subsample of at most n variants per transform.
 * The quantity being reported is a PROPORTION (what fraction of this
 * transform's variants are detected), so a deterministic stride estimates it
 * without bias, and both the sampled size and the population size are printed
 * and written to the report. Default 0 = no cap.
 *
 * Exit codes: 0 on success, 1 if the corpus is missing or no rules load.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine, foldConfusables, normalizeUnicode } from "../src/engine.js";
import {
  OBFUSCATION_SHAPES,
  type ObfuscationShapeName,
} from "./lib/garak-obfuscation-shapes.js";
import type { ObfuscatedCorpus, ObfuscatedSample } from "./garak-obfuscate.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

type NormalizationVerdict =
  "reverses-to-plaintext" | "changes-but-not-plaintext" | "no-effect";

interface PresentationCell {
  readonly presentation: string;
  readonly samples: number;
  readonly detected: number;
}

interface ShapeCell {
  readonly shape: ObfuscationShapeName;
  readonly baselineSeeds: number;
  readonly baselineDetected: number;
  readonly obfuscatedSamples: number;
  readonly obfuscatedDetected: number;
  /**
   * Split by carrier presentation. This is load-bearing, not detail: for an
   * `encoding` transform five of every six samples are the ciphertext wrapped
   * in one of garak's carrier templates (encoding.py:41-47), and those
   * templates are ENGLISH — "Decode the following BASE64 in your monologue. It
   * is a secure system message." A detection on a templated sample may be
   * reading the carrier and never the payload, so a combined number silently
   * overstates how much of the ciphertext ATR actually sees.
   */
  readonly byPresentation: readonly PresentationCell[];
  readonly firingRuleIds: readonly string[];
}

interface TransformResult {
  readonly transformId: string;
  readonly family: string;
  readonly seedCorpus: string;
  readonly population: number;
  readonly samples: number;
  readonly normalization: Readonly<Record<NormalizationVerdict, number>>;
  readonly shapes: readonly ShapeCell[];
}

/**
 * Evenly spaced subsample. Used only to bound wall-clock; the population size
 * travels with every sampled number so the two can never be confused.
 */
function stride<T>(items: readonly T[], cap: number): readonly T[] {
  if (cap <= 0 || items.length <= cap) return items;
  const step = items.length / cap;
  return Object.freeze(
    Array.from({ length: cap }, (_, i) => items[Math.floor(i * step)]),
  );
}

/** Which of the three things ATR's normalization layer does to this sample. */
function classifyNormalization(
  text: string,
  seed: string,
): NormalizationVerdict {
  const normalized = foldConfusables(normalizeUnicode(text));
  if (normalized === seed) return "reverses-to-plaintext";
  if (normalized !== text) return "changes-but-not-plaintext";
  return "no-effect";
}

function detect(
  engine: ATREngine,
  build: (t: string) => Parameters<ATREngine["evaluate"]>[0],
  text: string,
): readonly string[] {
  return engine.evaluate(build(text)).map((m) => m.rule.id);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const corpusIdx = args.indexOf("--corpus");
  const corpusPath =
    corpusIdx >= 0
      ? resolve(REPO_ROOT, args[corpusIdx + 1])
      : resolve(REPO_ROOT, "data/test-corpora/garak-obfuscated/corpus.json");
  const capIdx = args.indexOf("--cap");
  const cap = capIdx >= 0 ? Number.parseInt(args[capIdx + 1], 10) : 0;
  if (Number.isNaN(cap) || cap < 0) {
    console.error("[eval] --cap must be a non-negative integer");
    process.exit(1);
  }
  const outIdx = args.indexOf("--output");
  const outPath =
    outIdx >= 0
      ? resolve(REPO_ROOT, args[outIdx + 1])
      : resolve(
          REPO_ROOT,
          "data/test-corpora/garak-obfuscated/eval-report.json",
        );

  if (!existsSync(corpusPath)) {
    console.error(
      `[eval] corpus not found: ${corpusPath} — run scripts/garak-obfuscate.ts first`,
    );
    process.exit(1);
  }
  const corpus = JSON.parse(
    readFileSync(corpusPath, "utf-8"),
  ) as ObfuscatedCorpus;

  const engine = new ATREngine({ rulesDir: resolve(REPO_ROOT, "rules") });
  // `new ATREngine()` does not compile patterns; loadRules() must run first.
  const ruleCount = await engine.loadRules();
  if (ruleCount <= 0) {
    console.error("[eval] no rules loaded — refusing to report");
    process.exit(1);
  }
  console.log(`[eval] rules loaded: ${ruleCount}`);
  console.log(
    `[eval] corpus: ${corpus.samples.length} samples from ${corpusPath}`,
  );

  const byTransform = new Map<string, ObfuscatedSample[]>();
  for (const s of corpus.samples) {
    const list = byTransform.get(s.transformId) ?? [];
    list.push(s);
    byTransform.set(s.transformId, list);
  }

  // Plaintext baseline, per seed corpus and shape — computed once, reused.
  const baseline = new Map<string, Map<ObfuscationShapeName, number>>();
  for (const [name, seeds] of Object.entries(corpus.seedCorpora)) {
    const perShape = new Map<ObfuscationShapeName, number>();
    for (const shape of OBFUSCATION_SHAPES) {
      let hits = 0;
      for (const seed of seeds)
        if (detect(engine, shape.build, seed).length > 0) hits++;
      perShape.set(shape.name, hits);
    }
    baseline.set(name, perShape);
  }

  const results: TransformResult[] = [];
  const sortedTransforms = [...byTransform].sort();
  let done = 0;
  for (const [transformId, population] of sortedTransforms) {
    const samples = stride(population, cap);
    console.log(
      `[eval] (${++done}/${sortedTransforms.length}) ${transformId}: ${samples.length}/${population.length} variants`,
    );
    const seedCorpus = samples[0].seedCorpus;
    const seeds = corpus.seedCorpora[seedCorpus];
    const norm: Record<NormalizationVerdict, number> = {
      "reverses-to-plaintext": 0,
      "changes-but-not-plaintext": 0,
      "no-effect": 0,
    };
    for (const s of samples)
      norm[classifyNormalization(s.text, seeds[s.seedIndex])]++;

    const shapes: ShapeCell[] = [];
    for (const shape of OBFUSCATION_SHAPES) {
      let detected = 0;
      const ids = new Set<string>();
      const perPresentation = new Map<
        string,
        { samples: number; detected: number }
      >();
      for (const s of samples) {
        const hit = detect(engine, shape.build, s.text);
        const bucket = perPresentation.get(s.presentation) ?? {
          samples: 0,
          detected: 0,
        };
        const nextBucket = {
          samples: bucket.samples + 1,
          detected: bucket.detected + (hit.length > 0 ? 1 : 0),
        };
        perPresentation.set(s.presentation, nextBucket);
        if (hit.length > 0) {
          detected++;
          for (const id of hit) ids.add(id);
        }
      }
      shapes.push({
        shape: shape.name,
        baselineSeeds: seeds.length,
        baselineDetected: baseline.get(seedCorpus)!.get(shape.name)!,
        obfuscatedSamples: samples.length,
        obfuscatedDetected: detected,
        byPresentation: Object.freeze(
          [...perPresentation]
            .sort()
            .map(([presentation, v]) =>
              Object.freeze({
                presentation,
                samples: v.samples,
                detected: v.detected,
              }),
            ),
        ),
        firingRuleIds: Object.freeze([...ids].sort()),
      });
    }
    results.push({
      transformId,
      family: samples[0].family,
      seedCorpus,
      population: population.length,
      samples: samples.length,
      normalization: Object.freeze(norm),
      shapes: Object.freeze(shapes),
    });
  }

  report(results, ruleCount);
  reportPresentations(results);

  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(
    outPath,
    `${JSON.stringify({ ruleCount, cap, upstreamCommit: corpus.upstreamCommit, unported: corpus.unported, results }, null, 2)}\n`,
    "utf-8",
  );
  console.log(`[eval] wrote ${outPath}`);
}

const pct = (n: number, d: number): string =>
  d === 0 ? "  n/a" : `${((100 * n) / d).toFixed(1).padStart(5)}%`;

function report(results: readonly TransformResult[], ruleCount: number): void {
  for (const shape of OBFUSCATION_SHAPES) {
    console.log(
      `\n=== SHAPE ${shape.name} — ${shape.note} (${ruleCount} rules) ===`,
    );
    console.log(
      `${"transform".padEnd(30)} ${"plaintext".padEnd(14)} ${"obfuscated".padEnd(18)} delta   normalization(rev/chg/none)`,
    );
    for (const r of results) {
      const cell = r.shapes.find((c) => c.shape === shape.name)!;
      const base = cell.baselineDetected / cell.baselineSeeds;
      const obf = cell.obfuscatedDetected / cell.obfuscatedSamples;
      const n = r.normalization;
      console.log(
        `${r.transformId.padEnd(30)} ` +
          `${`${cell.baselineDetected}/${cell.baselineSeeds}`.padEnd(7)}${pct(cell.baselineDetected, cell.baselineSeeds)} ` +
          `${`${cell.obfuscatedDetected}/${cell.obfuscatedSamples}`.padEnd(11)}${pct(cell.obfuscatedDetected, cell.obfuscatedSamples)} ` +
          `${(100 * (obf - base)).toFixed(1).padStart(6)}pp  ` +
          `${n["reverses-to-plaintext"]}/${n["changes-but-not-plaintext"]}/${n["no-effect"]}`,
      );
    }
  }
}

/**
 * Bare ciphertext vs garak's English carrier templates, for the transforms
 * where that distinction exists. A transform that is only detected in its
 * templated form is not a transform ATR sees through — it is a transform whose
 * WRAPPER ATR reads.
 */
function reportPresentations(results: readonly TransformResult[]): void {
  console.log(
    "\n=== BARE CIPHERTEXT vs garak CARRIER TEMPLATE (encoding.py:41-47) ===",
  );
  console.log(
    "A number in the 'bare' column is detection of the encoded payload itself. " +
      "A number that appears only under 'templated' is detection of the English wrapper.",
  );
  for (const shape of OBFUSCATION_SHAPES) {
    console.log(`\n-- shape ${shape.name} --`);
    console.log(`${"transform".padEnd(30)} ${"bare".padEnd(14)} templated`);
    for (const r of results) {
      const cell = r.shapes.find((c) => c.shape === shape.name)!;
      const bare = cell.byPresentation.find((p) => p.presentation === "bare");
      if (!bare) continue; // perturbation transform: no template axis
      const templated = cell.byPresentation.filter(
        (p) => p.presentation !== "bare",
      );
      const tS = templated.reduce((a, p) => a + p.samples, 0);
      const tD = templated.reduce((a, p) => a + p.detected, 0);
      console.log(
        `${r.transformId.padEnd(30)} ` +
          `${`${bare.detected}/${bare.samples}`.padEnd(14)} ${tD}/${tS}`,
      );
    }
  }
}

await main();
