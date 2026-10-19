#!/usr/bin/env npx tsx
/**
 * bench-evaluate-latency.ts
 *
 * Times single ATREngine.evaluate() calls with the shipped rule set, in the
 * hunt lane (every maturity, the engine default) and the enforce lane (stable
 * rules only), on three committed corpora of very different input length.
 *
 * LIMITATIONS.md and THREAT-MODEL.md describe evaluation cost in orders of
 * magnitude, not as a figure: the figure depends on the hardware, the lane,
 * the length of the input and the size of the rule set on the day. This script
 * is how to get the figure for your own hardware.
 *
 * It is NOT what the `latency_ms` block in data/measurements/ records. The
 * eval harness times one corpus SAMPLE inside a full benchmark run: several
 * event shapes, a skill scan and, when the optional embedding model is
 * installed, an embedding pass, on whichever machine ran it. Those figures
 * are not comparable with one evaluate() call.
 *
 * Usage:  npx tsx scripts/bench-evaluate-latency.ts
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LANES = ["hunt", "enforce"] as const;
const WARMUP_PASSES = 3;
const WARMUP_SAMPLES = 50;

interface Corpus {
  readonly name: string;
  readonly texts: readonly string[];
}

function listMarkdown(dir: string): readonly string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return listMarkdown(path);
    return name.endsWith(".md") ? [path] : [];
  });
}

function loadCorpora(): readonly Corpus[] {
  const pint = JSON.parse(readFileSync(join(ROOT, "data/pint-benchmark/pint-corpus.json"), "utf8")) as {
    text: string;
    label: boolean;
  }[];
  const garak = JSON.parse(readFileSync(join(ROOT, "data/test-corpora/garak-full/inthewild.json"), "utf8")) as {
    prompts: string[];
  };
  const skills = listMarkdown(join(ROOT, "data/skill-benchmark/benign")).map((p) => readFileSync(p, "utf8"));
  return [
    { name: "PINT-format benign prompts", texts: pint.filter((s) => !s.label).map((s) => s.text) },
    { name: "garak in-the-wild prompts", texts: garak.prompts },
    { name: "benign SKILL.md files", texts: skills },
  ];
}

const toEvent = (content: string): AgentEvent => ({
  type: "llm_input",
  timestamp: new Date().toISOString(),
  content,
});

function percentile(sorted: readonly number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

function timeCorpus(engine: ATREngine, corpus: Corpus): string {
  const warmup = corpus.texts.slice(0, WARMUP_SAMPLES);
  for (let pass = 0; pass < WARMUP_PASSES; pass++) warmup.forEach((t) => engine.evaluate(toEvent(t)));
  const timings = corpus.texts.map((t) => {
    const event = toEvent(t);
    const start = performance.now();
    engine.evaluate(event);
    return performance.now() - start;
  });
  const sorted = [...timings].sort((a, b) => a - b);
  const avgChars = Math.round(corpus.texts.reduce((n, t) => n + t.length, 0) / corpus.texts.length);
  const ms = (v: number) => v.toFixed(2).padStart(8);
  return (
    `  ${corpus.name.padEnd(28)} n=${String(corpus.texts.length).padStart(4)}  avg ${String(avgChars).padStart(5)} chars` +
    `  p50 ${ms(percentile(sorted, 50))}  p90 ${ms(percentile(sorted, 90))}  p99 ${ms(percentile(sorted, 99))}` +
    `  max ${ms(sorted[sorted.length - 1])} ms`
  );
}

async function main(): Promise<void> {
  const corpora = loadCorpora();
  for (const lane of LANES) {
    const engine = new ATREngine({ lane });
    const loadStart = performance.now();
    const rules = await engine.loadRules();
    const loadMs = performance.now() - loadStart;
    const firstStart = performance.now();
    engine.evaluate(toEvent(corpora[0].texts[0]));
    const firstMs = performance.now() - firstStart;
    console.log(
      `\nlane ${lane}: ${rules} rules loaded in ${loadMs.toFixed(0)} ms; first evaluate() ` +
        `${firstMs.toFixed(0)} ms (compiles patterns not yet cached in this process). One evaluate() call per input:`,
    );
    corpora.forEach((corpus) => console.log(timeCorpus(engine, corpus)));
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
