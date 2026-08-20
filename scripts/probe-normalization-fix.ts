#!/usr/bin/env npx tsx
/**
 * probe-normalization-fix.ts — measure what the PROPOSED carrier decode
 * (scripts/lib/carrier-decode.ts) would buy, and what it would cost.
 *
 * BENEFIT is measured on the obfuscated garak corpus: how many samples of each
 * transform are detected today, and how many would be detected if the engine
 * also saw the decoded form.
 *
 * COST is measured on the same benign corpora the false-positive gates charge
 * rules against (MEASUREMENT_CORPORA in src/quality/action-eligibility.ts):
 * how many benign samples the decode changes at all, and how many go from
 * clean to flagged. A normalization change is charged for false positives on
 * every one of the 784 rules at once, which is exactly why it must be measured
 * before it is proposed and not after.
 *
 * MODEL OF THE ENGINE CHANGE: src/engine.ts:902,918 already tests each
 * condition against BOTH the normalized field value and the raw one, so adding
 * a decode step can only add matches, never remove them. This probe reproduces
 * that OR by scoring `detected(raw) || detected(decodeCarriers(raw))`. It does
 * not modify src/ — the point is to have the number before touching the engine.
 *
 * Usage:
 *   npx tsx scripts/probe-normalization-fix.ts [--corpus <path>]
 * Exit codes: 0 on success, 1 if a corpus is missing or no rules load.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import { OBFUSCATION_SHAPES } from "./lib/garak-obfuscation-shapes.js";
import { decodeCarriers } from "./lib/carrier-decode.js";
import { loadBenignSamples, MEASUREMENT_CORPORA } from "./lib/benign-corpus.js";
import type { ObfuscatedCorpus } from "./garak-obfuscate.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const args = process.argv.slice(2);
const corpusIdx = args.indexOf("--corpus");
const CORPUS_PATH =
  corpusIdx >= 0
    ? resolve(REPO_ROOT, args[corpusIdx + 1])
    : resolve(REPO_ROOT, "data/test-corpora/garak-obfuscated/corpus.json");

if (!existsSync(CORPUS_PATH)) {
  console.error(
    `[normfix] corpus not found: ${CORPUS_PATH} — run scripts/garak-obfuscate.ts first`,
  );
  process.exit(1);
}

const engine = new ATREngine({ rulesDir: resolve(REPO_ROOT, "rules") });
const ruleCount = await engine.loadRules();
if (ruleCount <= 0) {
  console.error("[normfix] no rules loaded — refusing to report");
  process.exit(1);
}
console.log(`[normfix] rules loaded: ${ruleCount}`);

const anyShapeDetects = (text: string): boolean =>
  OBFUSCATION_SHAPES.some((s) => engine.evaluate(s.build(text)).length > 0);

const detectsOnShape = (shapeName: string, text: string): boolean => {
  const shape = OBFUSCATION_SHAPES.find((s) => s.name === shapeName);
  if (!shape) throw new Error(`unknown shape: ${shapeName}`);
  return engine.evaluate(shape.build(text)).length > 0;
};

// -------------------------------------------------------------------------
// BENEFIT
// -------------------------------------------------------------------------
const corpus = JSON.parse(
  readFileSync(CORPUS_PATH, "utf-8"),
) as ObfuscatedCorpus;

/** Only the transforms the decode is even aimed at; the rest would be noise. */
const TARGETED = new Set([
  "badchars-deletion",
  "smuggling-unicode-tags",
  "smuggling-variant-selectors",
  "smuggling-sneaky-bits",
]);

interface Row {
  readonly transformId: string;
  readonly shape: string;
  readonly population: number;
  readonly samples: number;
  readonly before: number;
  readonly after: number;
  readonly decodeChanged: number;
}

/**
 * Deterministic stride sample. badchars-deletion alone is 3,024 variants and
 * every one costs three engine evaluations twice over; the ratio being measured
 * ("what fraction of this transform's variants are detected") is a proportion,
 * so an evenly spaced subsample estimates it without bias. The population size
 * is printed next to the sampled size so no reader mistakes one for the other.
 */
const SAMPLE_CAP = 300;
function stride<T>(items: readonly T[], cap: number): readonly T[] {
  if (items.length <= cap) return items;
  const step = items.length / cap;
  return Object.freeze(
    Array.from({ length: cap }, (_, i) => items[Math.floor(i * step)]),
  );
}

const rows: Row[] = [];
for (const transformId of TARGETED) {
  const population = corpus.samples.filter(
    (s) => s.transformId === transformId,
  );
  const samples = stride(population, SAMPLE_CAP);
  if (samples.length === 0) continue;
  const decoded = samples.map((s) => decodeCarriers(s.text));
  const changed = samples.filter((s, i) => decoded[i] !== s.text).length;
  for (const shape of OBFUSCATION_SHAPES) {
    let before = 0;
    let after = 0;
    for (let i = 0; i < samples.length; i++) {
      const hitRaw = detectsOnShape(shape.name, samples[i].text);
      if (hitRaw) before++;
      if (hitRaw || detectsOnShape(shape.name, decoded[i])) after++;
    }
    rows.push({
      transformId,
      shape: shape.name,
      population: population.length,
      samples: samples.length,
      before,
      after,
      decodeChanged: changed,
    });
  }
}

console.log("");
console.log("BENEFIT — detection on the obfuscated corpus, PER EVENT SHAPE");
console.log(
  `${"transform".padEnd(30)} ${"shape".padEnd(17)} ${"sampled/pop".padEnd(13)} ${"today".padEnd(17)} ${"with decode".padEnd(17)} decode altered`,
);
for (const r of rows.sort(
  (a, b) =>
    a.transformId.localeCompare(b.transformId) ||
    a.shape.localeCompare(b.shape),
)) {
  const p = (n: number): string =>
    `${n}/${r.samples} (${((100 * n) / r.samples).toFixed(1)}%)`;
  console.log(
    `${r.transformId.padEnd(30)} ${r.shape.padEnd(17)} ${`${r.samples}/${r.population}`.padEnd(13)} ${p(r.before).padEnd(17)} ${p(r.after).padEnd(17)} ${r.decodeChanged}/${r.samples}`,
  );
}

// -------------------------------------------------------------------------
// COST
// -------------------------------------------------------------------------
const benign = loadBenignSamples(REPO_ROOT);
console.log("");
console.log(
  `COST — benign corpora ${MEASUREMENT_CORPORA.join(", ")} (${benign.length} samples)`,
);
if (benign.length === 0) {
  console.error(
    "[normfix] benign corpora are empty — cost is UNMEASURED, not zero",
  );
  process.exit(1);
}

let touched = 0;
let cleanToFlagged = 0;
const newlyFlagged: string[] = [];
for (const sample of benign) {
  const decoded = decodeCarriers(sample);
  if (decoded === sample) continue;
  touched++;
  if (anyShapeDetects(sample)) continue;
  if (anyShapeDetects(decoded)) {
    cleanToFlagged++;
    if (newlyFlagged.length < 5) newlyFlagged.push(sample.slice(0, 160));
  }
}
console.log(
  `benign samples the decode alters at all: ${touched}/${benign.length}`,
);
console.log(
  `benign samples that go clean -> flagged: ${cleanToFlagged}/${benign.length}`,
);
for (const s of newlyFlagged)
  console.log(`  newly flagged: ${JSON.stringify(s)}`);
console.log("");
console.log(
  cleanToFlagged === 0
    ? "VERDICT: the decode adds no false positive on the corpora the FP gates use."
    : `VERDICT: the decode costs ${cleanToFlagged} new false positive(s) — do not ship as-is.`,
);
