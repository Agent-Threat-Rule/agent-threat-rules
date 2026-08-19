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
  console.error(`[normfix] corpus not found: ${CORPUS_PATH} — run scripts/garak-obfuscate.ts first`);
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

// -------------------------------------------------------------------------
// BENEFIT
// -------------------------------------------------------------------------
const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as ObfuscatedCorpus;

/** Only the transforms the decode is even aimed at; the rest would be noise. */
const TARGETED = new Set([
  "badchars-deletion",
  "smuggling-unicode-tags",
  "smuggling-variant-selectors",
  "smuggling-sneaky-bits",
]);

interface Row {
  readonly transformId: string;
  readonly samples: number;
  readonly before: number;
  readonly after: number;
  readonly decodeChanged: number;
}

const rows: Row[] = [];
for (const transformId of TARGETED) {
  const samples = corpus.samples.filter((s) => s.transformId === transformId);
  if (samples.length === 0) continue;
  let before = 0;
  let after = 0;
  let changed = 0;
  for (const s of samples) {
    const decoded = decodeCarriers(s.text);
    if (decoded !== s.text) changed++;
    const hitRaw = anyShapeDetects(s.text);
    if (hitRaw) before++;
    if (hitRaw || anyShapeDetects(decoded)) after++;
  }
  rows.push({ transformId, samples: samples.length, before, after, decodeChanged: changed });
}

console.log("");
console.log("BENEFIT — detection on the obfuscated corpus (union of all three shapes)");
console.log(
  `${"transform".padEnd(30)} ${"samples".padEnd(9)} ${"today".padEnd(16)} ${"with decode".padEnd(16)} decode altered`,
);
for (const r of rows.sort((a, b) => a.transformId.localeCompare(b.transformId))) {
  const p = (n: number): string => `${n}/${r.samples} (${((100 * n) / r.samples).toFixed(1)}%)`;
  console.log(
    `${r.transformId.padEnd(30)} ${String(r.samples).padEnd(9)} ${p(r.before).padEnd(16)} ${p(r.after).padEnd(16)} ${r.decodeChanged}/${r.samples}`,
  );
}

// -------------------------------------------------------------------------
// COST
// -------------------------------------------------------------------------
const benign = loadBenignSamples(REPO_ROOT);
console.log("");
console.log(`COST — benign corpora ${MEASUREMENT_CORPORA.join(", ")} (${benign.length} samples)`);
if (benign.length === 0) {
  console.error("[normfix] benign corpora are empty — cost is UNMEASURED, not zero");
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
console.log(`benign samples the decode alters at all: ${touched}/${benign.length}`);
console.log(`benign samples that go clean -> flagged: ${cleanToFlagged}/${benign.length}`);
for (const s of newlyFlagged) console.log(`  newly flagged: ${JSON.stringify(s)}`);
console.log("");
console.log(
  cleanToFlagged === 0
    ? "VERDICT: the decode adds no false positive on the corpora the FP gates use."
    : `VERDICT: the decode costs ${cleanToFlagged} new false positive(s) — do not ship as-is.`,
);
