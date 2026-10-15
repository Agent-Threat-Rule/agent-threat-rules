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
import { join, relative, sep } from "node:path";
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

/** One sample, with where it came from. */
export interface CorpusRecord {
  readonly text: string;
  /** Path relative to the root the corpus was read from, with forward slashes. */
  readonly file: string;
  /** 1-based physical line of a .jsonl record; null for a .md file, which is one sample. */
  readonly line: number | null;
  /** The trimmed .jsonl line, or the whole .md file: what the sample was parsed from. */
  readonly raw: string;
  readonly source: string | null;
  readonly sourceId: string | null;
}

function jsonlRecord(file: string, line: number, raw: string): CorpusRecord | null {
  // Same acceptance as loadCorpusTexts, including that a line parsing to a
  // non-object (`null`, `5`) is skipped by the property access throwing.
  try {
    const obj = JSON.parse(raw) as { text?: unknown; source?: unknown; source_id?: unknown };
    if (typeof obj.text !== "string" || obj.text.length === 0) return null;
    const id = obj.source_id;
    return {
      text: obj.text,
      file,
      line,
      raw,
      source: typeof obj.source === "string" ? obj.source : null,
      sourceId: typeof id === "string" || typeof id === "number" ? String(id) : null,
    };
  } catch {
    return null;
  }
}

/**
 * The samples of one corpus path under `root`, as loadCorpusTexts reads them
 * and in the same order, each with its file, line and recorded source.
 * Provenance only: callers that count samples must still go through
 * loadCorpusTexts, and scripts/remeasure-benign-fp.ts asserts that the two
 * agree text for text.
 */
export function loadCorpusRecords(root: string, corpus: string): readonly CorpusRecord[] {
  const path = join(root, corpus);
  if (!existsSync(path)) return [];
  const files = statSync(path).isDirectory() ? collectCorpusFiles(path) : [path];
  const out: CorpusRecord[] = [];
  for (const full of files) {
    let raw: string;
    try {
      raw = readFileSync(full, "utf-8");
    } catch {
      continue;
    }
    const file = relative(root, full).split(sep).join("/");
    if (full.endsWith(".md")) {
      out.push({ text: raw, file, line: null, raw, source: null, sourceId: null });
      continue;
    }
    raw.split("\n").forEach((line, i) => {
      const trimmed = line.trim();
      const rec = trimmed === "" ? null : jsonlRecord(file, i + 1, trimmed);
      if (rec !== null) out.push(rec);
    });
  }
  return out;
}

/** Every benign sample the FP gate would score a rule against. */
export function loadBenignSamples(repoRoot: string): readonly string[] {
  const samples: string[] = [];
  for (const corpus of MEASUREMENT_CORPORA) {
    samples.push(...loadCorpusTexts(join(repoRoot, corpus)));
  }
  return samples;
}
