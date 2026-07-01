#!/usr/bin/env npx tsx
/**
 * auto-regex.ts
 *
 * Given a proposal stub with populated test_cases.true_positives +
 * true_negatives (and ideally _red_team_probe_submission metadata),
 * generate a candidate regex and run it through the full ATR quality
 * gate. If it passes — 0 FP on benign + research-mention + extended
 * benign corpora, 0 cross-rule conflicts, matches all own TPs — write
 * the regex into the proposal's detection.conditions and return
 * success. If it fails, the proposal stays a stub for human review.
 *
 * The point of this script: closes the "you submitted a probe and it
 * just sits there as a stub" gap. With auto-regex, a clean probe
 * submission can become a real merged ATR rule end-to-end without
 * human regex authoring — but only when the gate is happy.
 *
 * Algorithm:
 *   1. Tokenize each positive example into n-gram phrases (3-7 words,
 *      4-60 chars).
 *   2. Score each phrase by:
 *      - Coverage: fraction of positive examples it appears in.
 *      - Selectivity: 1 minus fraction of negative examples it appears in.
 *      - Length: longer is better (selectivity proxy).
 *   3. Greedy-pick phrases until all positive examples are covered.
 *   4. Build alternation regex from picked phrases, escape special chars,
 *      add word boundaries.
 *   5. Run the candidate through check-rules-safety-style FP gate
 *      (benign + extended benign + research-mention + cross-rule).
 *   6. If pass, write to proposal. If fail, try a tighter variant
 *      (require both n-grams from same example, add anchors). Up to
 *      MAX_VARIANTS attempts. After that, leave the proposal alone.
 *
 * Usage:
 *   npx tsx scripts/auto-regex.ts --file proposals/red-team-probes/foo.proposal.yaml
 *   npx tsx scripts/auto-regex.ts --file <path> --write    # write regex to file
 *
 * Exit codes:
 *   0 success — gate passed, regex written (or --write off → dry-run preview)
 *   1 fatal — couldn't parse file / required fields missing
 *   2 no-pass — generated all variants but none cleared the gate
 */

import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const BENIGN_DIR = resolve(REPO_ROOT, "data/skill-benchmark/benign");
const EXTENDED_DIR = resolve(REPO_ROOT, "data/benign-corpus-extended");
const RESEARCH_FILE = resolve(REPO_ROOT, "data/research-mentions/corpus.jsonl");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const FILE = opt("--file");
const WRITE = flag("--write");
const VERBOSE = flag("--verbose");
const MAX_VARIANTS = 4;

interface ProposalDoc {
  id?: string;
  title?: string;
  test_cases?: {
    true_positives?: Array<string | { input?: string }>;
    true_negatives?: Array<string | { input?: string }>;
  };
  detection?: {
    condition?: string;
    conditions?: unknown[];
  };
  [k: string]: unknown;
}

function fail(msg: string, code = 1): never {
  console.error(`error: ${msg}`);
  process.exit(code);
}

function extractTexts(
  arr: Array<string | { input?: string }> | undefined,
): string[] {
  if (!arr) return [];
  return arr
    .map((x) => (typeof x === "string" ? x : (x?.input ?? "")))
    .filter((s): s is string => typeof s === "string" && s.length > 0);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// --- phrase extraction ----------------------------------------------------

interface PhraseScore {
  phrase: string;
  coverage: number; // fraction of positives containing it
  fpRate: number; // fraction of negatives containing it
  length: number;
}

function extractNgrams(text: string, minLen = 4, maxLen = 60): Set<string> {
  // Word n-grams (1..7 words), each n-gram itself between minLen and
  // maxLen characters. Lowercase, single-space normalized.
  const norm = text.toLowerCase().replace(/\s+/g, " ").trim();
  const words = norm.split(" ").filter((w) => w.length > 0);
  const out = new Set<string>();
  for (let n = 1; n <= 7 && n <= words.length; n++) {
    for (let i = 0; i + n <= words.length; i++) {
      const phrase = words.slice(i, i + n).join(" ");
      if (phrase.length >= minLen && phrase.length <= maxLen) {
        out.add(phrase);
      }
    }
  }
  return out;
}

function scorePhrases(positives: string[], negatives: string[]): PhraseScore[] {
  const phraseToPositives = new Map<string, number>();
  for (const p of positives) {
    const grams = extractNgrams(p);
    for (const g of grams) {
      phraseToPositives.set(g, (phraseToPositives.get(g) ?? 0) + 1);
    }
  }
  const phraseToNegatives = new Map<string, number>();
  for (const n of negatives) {
    const lower = n.toLowerCase();
    for (const g of phraseToPositives.keys()) {
      if (lower.includes(g)) {
        phraseToNegatives.set(g, (phraseToNegatives.get(g) ?? 0) + 1);
      }
    }
  }
  const scored: PhraseScore[] = [];
  for (const [phrase, posCount] of phraseToPositives) {
    const coverage = posCount / positives.length;
    const fpRate =
      (phraseToNegatives.get(phrase) ?? 0) / Math.max(1, negatives.length);
    scored.push({ phrase, coverage, fpRate, length: phrase.length });
  }
  return scored;
}

/**
 * Greedy set-cover: pick the highest-scoring phrase that covers any
 * still-uncovered positive example, repeat until all positives covered
 * or we run out of zero-FP-rate phrases.
 *
 * `strictness` tunes the acceptable FP rate per phrase (0 = strict,
 * 1 = lenient). Tighter variants raise strictness; the gate ultimately
 * validates the whole regex against the full corpora anyway.
 */
function selectPhrases(
  positives: string[],
  negatives: string[],
  strictness: number,
): string[] {
  const maxFpPerPhrase = strictness; // proportion of negatives allowed per phrase
  const scored = scorePhrases(positives, negatives).filter(
    (s) => s.fpRate <= maxFpPerPhrase,
  );
  scored.sort((a, b) => {
    // Prioritize selectivity (low fpRate), then length, then coverage.
    if (a.fpRate !== b.fpRate) return a.fpRate - b.fpRate;
    if (a.length !== b.length) return b.length - a.length;
    return b.coverage - a.coverage;
  });

  const covered = new Set<number>();
  const picked: string[] = [];
  const lowerPositives = positives.map((p) => p.toLowerCase());

  for (const s of scored) {
    if (covered.size === positives.length) break;
    let newCoverage = 0;
    for (let i = 0; i < lowerPositives.length; i++) {
      if (covered.has(i)) continue;
      if (lowerPositives[i].includes(s.phrase)) newCoverage += 1;
    }
    if (newCoverage === 0) continue;
    picked.push(s.phrase);
    for (let i = 0; i < lowerPositives.length; i++) {
      if (!covered.has(i) && lowerPositives[i].includes(s.phrase)) {
        covered.add(i);
      }
    }
    if (picked.length >= 8) break; // cap regex complexity
  }
  return picked;
}

function buildRegex(phrases: string[], variantIdx: number): string {
  if (phrases.length === 0) return "";
  const escaped = phrases.map(escapeRegex);
  switch (variantIdx) {
    case 0:
      // Plain alternation, case-insensitive
      return `(?i)(${escaped.join("|")})`;
    case 1:
      // Word-boundary anchored
      return `(?i)\\b(${escaped.join("|")})\\b`;
    case 2:
      // Whitespace-anchored (avoid partial-word false matches)
      return `(?i)(^|[\\s\\.\\,\\;\\:\\!\\?\\(\\[])(${escaped.join("|")})($|[\\s\\.\\,\\;\\:\\!\\?\\)\\]])`;
    case 3:
      // Require two phrases co-occurring (tightest)
      if (phrases.length < 2) return `(?i)\\b(${escaped.join("|")})\\b`;
      return `(?i)(?=.*${escaped[0]})(?=.*${escaped[1]})`;
    default:
      return `(?i)\\b(${escaped.join("|")})\\b`;
  }
}

// --- gate evaluation ------------------------------------------------------

interface GateResult {
  pass: boolean;
  ownTpCoverage: number;
  benignFp: number;
  extendedFp: number;
  researchFp: number;
  crossRuleConflicts: number;
  totalFp: number;
}

function compileRegex(pattern: string): RegExp | null {
  // Translate (?i) inline flag into JS flags
  let p = pattern;
  let flags = "";
  if (p.startsWith("(?i)")) {
    p = p.slice(4);
    flags = "i";
  }
  try {
    return new RegExp(p, flags);
  } catch {
    return null;
  }
}

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    let s;
    try {
      s = statSync(f);
    } catch {
      continue;
    }
    if (s.isDirectory()) out.push(...walkYaml(f));
    else if (s.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

interface ExternalTN {
  ownerId: string;
  text: string;
}
function loadExistingTNs(): ExternalTN[] {
  const out: ExternalTN[] = [];
  for (const f of walkYaml(RULES_DIR)) {
    let doc: unknown;
    try {
      doc = yaml.load(readFileSync(f, "utf-8"));
    } catch {
      continue;
    }
    const d = doc as {
      id?: string;
      test_cases?: { true_negatives?: Array<string | { input?: string }> };
    };
    const id = d.id ?? f;
    for (const t of d.test_cases?.true_negatives ?? []) {
      const text = typeof t === "string" ? t : (t?.input ?? "");
      if (typeof text === "string" && text.length > 0)
        out.push({ ownerId: id, text });
    }
  }
  return out;
}

function loadSamples(): {
  benign: string[];
  extended: string[];
  research: string[];
} {
  const benign: string[] = [];
  if (existsSync(BENIGN_DIR)) {
    for (const e of readdirSync(BENIGN_DIR)) {
      if (!e.endsWith(".md")) continue;
      try {
        benign.push(readFileSync(join(BENIGN_DIR, e), "utf-8"));
      } catch {
        continue;
      }
    }
  }
  const extended: string[] = [];
  if (existsSync(EXTENDED_DIR)) {
    for (const e of readdirSync(EXTENDED_DIR)) {
      if (!e.endsWith(".jsonl")) continue;
      try {
        const lines = readFileSync(join(EXTENDED_DIR, e), "utf-8").split("\n");
        for (const ln of lines) {
          const t = ln.trim();
          if (!t) continue;
          try {
            const j = JSON.parse(t) as { text?: string };
            if (typeof j.text === "string") extended.push(j.text);
          } catch {
            continue;
          }
        }
      } catch {
        continue;
      }
    }
  }
  const research: string[] = [];
  if (existsSync(RESEARCH_FILE)) {
    for (const ln of readFileSync(RESEARCH_FILE, "utf-8").split("\n")) {
      const t = ln.trim();
      if (!t) continue;
      try {
        const j = JSON.parse(t) as { text?: string };
        if (typeof j.text === "string") research.push(j.text);
      } catch {
        continue;
      }
    }
  }
  return { benign, extended, research };
}

function evaluateGate(
  pattern: string,
  tps: string[],
  samples: { benign: string[]; extended: string[]; research: string[] },
  existingTNs: ExternalTN[],
): GateResult {
  const re = compileRegex(pattern);
  if (!re)
    return {
      pass: false,
      ownTpCoverage: 0,
      benignFp: 0,
      extendedFp: 0,
      researchFp: 0,
      crossRuleConflicts: 0,
      totalFp: 0,
    };
  const ownHits = tps.filter((t) => re.test(t)).length;
  const benignFp = samples.benign.filter((s) => re.test(s)).length;
  const extendedFp = samples.extended.filter((s) => re.test(s)).length;
  const researchFp = samples.research.filter((s) => re.test(s)).length;
  const crossRuleConflicts = existingTNs.filter((t) => re.test(t.text)).length;
  const totalFp = benignFp + extendedFp + researchFp + crossRuleConflicts;
  return {
    pass: ownHits === tps.length && totalFp === 0,
    ownTpCoverage: ownHits / tps.length,
    benignFp,
    extendedFp,
    researchFp,
    crossRuleConflicts,
    totalFp,
  };
}

// --- proposal write-back --------------------------------------------------

function writeRegexIntoProposal(
  filePath: string,
  doc: ProposalDoc,
  pattern: string,
): void {
  // Build the new detection block as YAML, preserving the rest of the
  // file via re-serialisation through js-yaml.
  doc.detection = {
    condition: "any",
    false_positives: [],
    conditions: [
      {
        field: "content",
        match: "regex",
        value: pattern,
      },
    ],
  };
  // Drop any banner-only TODO comment. The auto-regex provenance is
  // captured under _auto_regex.
  (doc as Record<string, unknown>)._auto_regex = {
    generated_on: new Date().toISOString().slice(0, 10),
    pattern,
    method: "n-gram set cover + safety gate",
  };
  const yamlBody = yaml.dump(doc, {
    lineWidth: 100,
    noRefs: true,
    quotingType: '"',
  });
  const banner = `# ATR rule proposal -- detection regex auto-generated by scripts/auto-regex.ts
# A maintainer should still review the regex before promotion to rules/.
`;
  writeFileSync(filePath, banner + "\n" + yamlBody, "utf-8");
}

// --- main -----------------------------------------------------------------

async function main(): Promise<void> {
  if (!FILE) fail("--file <path> required");
  const abs = resolve(FILE!);
  if (!existsSync(abs)) fail(`file not found: ${abs}`);
  let doc: ProposalDoc;
  try {
    doc = yaml.load(readFileSync(abs, "utf-8")) as ProposalDoc;
  } catch (e) {
    fail(`could not parse YAML: ${e}`);
  }
  const tps = extractTexts(doc.test_cases?.true_positives);
  const tns = extractTexts(doc.test_cases?.true_negatives);
  if (tps.length === 0) fail("proposal has no true_positives");
  if (tns.length === 0) fail("proposal has no true_negatives");

  console.error(
    `[auto-regex] ${abs}: ${tps.length} TPs, ${tns.length} TNs — generating candidate regex…`,
  );

  const samples = loadSamples();
  const existingTNs = loadExistingTNs();
  console.error(
    `[auto-regex] gate corpora: ${samples.benign.length} benign, ${samples.extended.length} extended-benign, ${samples.research.length} research-mention, ${existingTNs.length} cross-rule TNs`,
  );

  let best: { variant: number; pattern: string; result: GateResult } | null =
    null;
  for (let variant = 0; variant < MAX_VARIANTS; variant++) {
    const strictness = 0.0 + variant * 0.05; // 0.00, 0.05, 0.10, 0.15
    const phrases = selectPhrases(tps, tns, strictness);
    if (phrases.length === 0) {
      if (VERBOSE)
        console.error(
          `[auto-regex] variant ${variant} (strictness=${strictness}): 0 phrases selected`,
        );
      continue;
    }
    const pattern = buildRegex(phrases, variant);
    const result = evaluateGate(pattern, tps, samples, existingTNs);
    console.error(
      `[auto-regex] variant ${variant}: ${phrases.length} phrases, ` +
        `tp=${Math.round(result.ownTpCoverage * 100)}%, fp=${result.totalFp} ` +
        `(benign=${result.benignFp} ext=${result.extendedFp} res=${result.researchFp} ` +
        `cross=${result.crossRuleConflicts}) — ${result.pass ? "PASS" : "fail"}`,
    );
    if (VERBOSE) console.error(`     pattern: ${pattern}`);
    if (result.pass) {
      best = { variant, pattern, result };
      break;
    }
    if (
      !best ||
      result.totalFp < best.result.totalFp ||
      (result.totalFp === best.result.totalFp &&
        result.ownTpCoverage > best.result.ownTpCoverage)
    ) {
      best = { variant, pattern, result };
    }
  }

  if (!best || !best.result.pass) {
    console.log(
      `::auto-regex-summary::${JSON.stringify({
        file: FILE,
        passed: false,
        reason: best
          ? `closest variant ${best.variant} still has ${best.result.totalFp} FP / ${Math.round(best.result.ownTpCoverage * 100)}% TP coverage`
          : "no candidate phrases met the per-phrase FP-rate threshold",
      })}`,
    );
    process.exit(2);
  }

  console.error(`[auto-regex] PASS — variant ${best.variant}: ${best.pattern}`);
  if (WRITE) {
    writeRegexIntoProposal(abs, doc, best.pattern);
    console.error(`[auto-regex] wrote regex to ${abs}`);
  } else {
    console.error(`[auto-regex] dry-run — pass --write to commit`);
  }
  console.log(
    `::auto-regex-summary::${JSON.stringify({
      file: FILE,
      passed: true,
      variant: best.variant,
      pattern: best.pattern,
      tp_coverage: best.result.ownTpCoverage,
      total_fp: best.result.totalFp,
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
