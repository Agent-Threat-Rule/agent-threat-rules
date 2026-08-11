/**
 * Loader for the benign corpora the false-positive gates charge rules against.
 *
 * The corpus PATHS are not defined here on purpose. They live in
 * MEASUREMENT_CORPORA (src/quality/action-eligibility.ts) and are what
 * scripts/gate-promotion-fp.ts scans and what corpusDigest() hashes. A second
 * list would let the FP gate and the visibility gate silently measure
 * different things -- and "these two numbers came from different corpora" is
 * exactly the failure this repo keeps paying for.
 *
 * Reading rules mirror gate-promotion-fp.ts exactly:
 *   - recurse into subdirectories (data/skill-benchmark/benign/ninja-legit/
 *     once hid 35 samples from a one-level walk),
 *   - .md files are one sample each,
 *   - .jsonl lines contribute their `text` field, if it is a non-empty string.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { MEASUREMENT_CORPORA } from "../../src/quality/action-eligibility.js";

export { MEASUREMENT_CORPORA };

/** Every corpus file under a directory tree, including subdirectories. */
export function collectCorpusFiles(dir: string): readonly string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...collectCorpusFiles(full));
    else if (entry.endsWith(".jsonl") || entry.endsWith(".md")) out.push(full);
  }
  return out.sort();
}

/** Sample texts from one corpus path (directory or single file). */
export function loadCorpusTexts(pathStr: string): readonly string[] {
  if (!existsSync(pathStr)) return [];
  const files = statSync(pathStr).isDirectory()
    ? collectCorpusFiles(pathStr)
    : [pathStr];
  const texts: string[] = [];
  for (const file of files) {
    let raw: string;
    try {
      raw = readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    if (file.endsWith(".md")) {
      texts.push(raw);
      continue;
    }
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed) as { text?: unknown };
        if (typeof obj.text === "string" && obj.text.length > 0) texts.push(obj.text);
      } catch {
        continue;
      }
    }
  }
  return texts;
}

/** Every benign sample the FP gate would score a rule against. */
export function loadBenignSamples(repoRoot: string): readonly string[] {
  const samples: string[] = [];
  for (const corpus of MEASUREMENT_CORPORA) {
    samples.push(...loadCorpusTexts(join(repoRoot, corpus)));
  }
  return samples;
}
