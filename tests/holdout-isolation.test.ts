/**
 * Holdout v1 stays out of sample.
 *
 * data/holdout/v1/ is only evidence while no rule has been written from it and
 * no gate trains on it. The build screened it against everything the repository
 * held at the time (scripts/holdout/build_holdout_v1.py). These tests keep it
 * that way afterwards:
 *
 *   1. The files are the ones the manifest names (sha256, sample counts).
 *   2. No rule's test cases or evasion tests contain a holdout sample, verbatim
 *      or as a near copy (half or more of its 5-word shingles). A rule author
 *      who pastes a holdout attack into true_positives has turned a held-out
 *      sample into a training sample; the remedy is a new holdout version, not
 *      an exception here.
 *   3. Nothing outside the measurement reads the directory. A gate, a miner or
 *      a corpus loader that picks it up would contaminate it without touching
 *      a rule.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";
import { HOLDOUT_REL_DIR, loadHoldout } from "../scripts/lib/holdout.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHINGLE = 5;
const NEAR_COPY = 0.5;

/** Files allowed to name the holdout directory. Everything else must not. */
const READERS = new Set([
  "scripts/lib/holdout.ts",
  "scripts/measure-holdout-evidence.ts",
  "scripts/holdout/build_holdout_v1.py",
  "tests/holdout-isolation.test.ts",
  ".github/workflows/holdout-evidence.yml",
]);

function normalize(s: string): string {
  return s.normalize("NFKC").toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}

function shingles(s: string): string[] {
  const words = normalize(s).match(/[\p{L}\p{N}_]+/gu) ?? [];
  if (words.length < SHINGLE) return words.length ? [words.join(" ")] : [];
  const out: string[] = [];
  for (let i = 0; i + SHINGLE <= words.length; i++) out.push(words.slice(i, i + SHINGLE).join(" "));
  return out;
}

function walk(dir: string, keep: (p: string) => boolean): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    if (e === "node_modules" || e === ".git" || e === "dist") continue;
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...walk(full, keep));
    else if (keep(full)) out.push(full);
  }
  return out;
}

function ruleTexts(): Array<{ file: string; text: string }> {
  const out: Array<{ file: string; text: string }> = [];
  for (const file of walk(join(REPO, "rules"), (p) => p.endsWith(".yaml"))) {
    const doc = parseYaml(readFileSync(file, "utf8")) as Record<string, unknown> | null;
    const cases: unknown[] = [];
    const tc = (doc?.["test_cases"] ?? {}) as Record<string, unknown>;
    for (const k of ["true_positives", "true_negatives"]) if (Array.isArray(tc[k])) cases.push(...(tc[k] as unknown[]));
    if (Array.isArray(doc?.["evasion_tests"])) cases.push(...(doc!["evasion_tests"] as unknown[]));
    for (const c of cases) {
      for (const v of Object.values((c ?? {}) as Record<string, unknown>)) {
        if (typeof v === "string" && v.length >= 8) out.push({ file: relative(REPO, file), text: v });
      }
    }
  }
  return out;
}

describe("holdout v1", () => {
  const holdout = loadHoldout(REPO);
  const samples = [...holdout.attack, ...holdout.benign];

  it("matches its manifest", () => {
    expect(holdout.attack.length).toBe(holdout.manifest.files["attack.jsonl"]!.samples);
    expect(holdout.benign.length).toBe(holdout.manifest.files["benign.jsonl"]!.samples);
    expect(new Set(samples.map((s) => s.id)).size).toBe(samples.length);
  });

  it("shares no text with any rule's test cases or evasion tests", () => {
    // Same direction as the build screen: a holdout sample is leaked when half
    // or more of ITS shingles appear in rule text. The reverse direction flags
    // every short rule string that shares one stock phrase ("ignore all previous
    // instructions") with some sample, which is not a copy.
    const texts = ruleTexts();
    const exact = new Map(texts.map((t) => [normalize(t.text), t.file]));
    const index = new Set<string>();
    for (const t of texts) for (const sh of shingles(t.text)) index.add(sh);
    const leaks: string[] = [];
    for (const s of samples) {
      const norm = normalize(s.text);
      if (exact.has(norm)) {
        leaks.push(`${s.id}: verbatim in ${exact.get(norm)}`);
        continue;
      }
      const sh = shingles(s.text);
      if (sh.length === 0) continue;
      const hit = sh.filter((x) => index.has(x)).length / sh.length;
      if (hit >= NEAR_COPY) leaks.push(`${s.id}: ${(hit * 100).toFixed(0)}% of its shingles are in rule test text`);
    }
    expect(leaks).toEqual([]);
  });

  it("is read by the measurement and nothing else", () => {
    const keep = (p: string) => /\.(ts|mts|js|mjs|py|ya?ml|sh)$/.test(p);
    const roots = ["scripts", "src", "tests", ".github", "python", "integrations"].map((d) => join(REPO, d));
    const offenders: string[] = [];
    for (const root of roots) {
      for (const file of walk(root, keep)) {
        const rel = relative(REPO, file);
        if (READERS.has(rel)) continue;
        if (readFileSync(file, "utf8").includes(HOLDOUT_REL_DIR) || readFileSync(file, "utf8").includes("data/holdout")) {
          offenders.push(rel);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
