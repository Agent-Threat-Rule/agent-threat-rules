#!/usr/bin/env npx tsx
/**
 * garak-miss-to-proposals.ts
 *
 * The "last mile" of the red-team pipeline: turn the agent-attack prompts that
 * ATR currently MISSES on the garak full benchmark into semantic-attack cluster
 * proposals that the T2 authoring pipeline (scripts/author-semantic-rules.ts,
 * the garak-clusters source) consumes to author method=semantic rules.
 *
 * WHY THIS SCRIPT EXISTS
 * ----------------------
 * author-semantic-rules.ts READS proposals/garak-clusters/*.proposal.yaml but
 * nothing in the repo WROTE them in a committed, repeatable way — the existing
 * proposals were a one-off, with absolute machine paths baked into the manifest.
 * This script is the missing, deterministic generator: report -> proposals.
 *
 * SCOPE DISCIPLINE (keep ATR in its lane)
 * ---------------------------------------
 * The garak corpus mixes agent-attack families (prompt injection / instruction
 * override / jailbreak persona / latent injection / system-prompt extraction /
 * encoding-obfuscated injection / web-markdown injection — IN ATR scope) with
 * content-safety families (snowball / harmbench / dra / malwaregen /
 * packagehallucination / badchars / sata / smuggling / lmrc / gcg / goat —
 * graphic violence, weapons, drug synthesis, hallucinated packages, toxic
 * content — NOT an agent threat, OUT of scope). ATR detects attacks ON the
 * agent, not harmful content a model might be asked to produce.
 *
 * The agent-attack allowlist here is the SAME set author-semantic-rules.ts uses
 * to admit garak clusters (GARAK_FAMILY_ALLOW). It is mirrored deliberately so
 * every proposal this script emits is one the consumer will actually accept —
 * emitting proposals the consumer rejects would just be noise. A per-sample
 * content-safety guard (also mirrored) drops any individual prompt that reads as
 * content-policy harm even inside an allowed family (e.g. a slur smuggled into
 * an `encoding` probe).
 *
 * GRANULARITY
 * -----------
 * One proposal per agent-attack family. A garak family IS a semantic attack
 * class, which is exactly what a T2 LLM-as-judge rule defines. The family's
 * missed prompts become true_positives (deduped, capped); benign negatives are
 * drawn from data/benign-code + a fixed agent-context benign set so the
 * consumer's 0-FP narrow-regex gate has something to test against.
 *
 * WHAT THIS SCRIPT DOES NOT DO
 * ----------------------------
 * It does NOT author rules, call any LLM, or touch rules/. It only writes
 * proposals. The LLM judge-prompt authoring + the deterministic 0-FP gate live
 * in author-semantic-rules.ts and run in CI with an API key. No fabrication.
 *
 * USAGE
 *   npx tsx scripts/garak-miss-to-proposals.ts                 # dry-run (no writes)
 *   npx tsx scripts/garak-miss-to-proposals.ts --write         # write proposals + manifest
 *   ... --report data/garak-benchmark/garak-full-report.json   # input report path
 *   ... --max-tp 40                                            # cap true_positives per family
 *   ... --out proposals/garak-clusters                         # output dir
 *
 * EXIT CODES
 *   0 success (wrote / would write >=0 proposals)
 *   1 fatal IO / parse error (missing report, unreadable corpus)
 *   2 report present but contained zero in-scope agent misses (nothing to do)
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const DEFAULT_REPORT = resolve(REPO_ROOT, "data/garak-benchmark/garak-full-report.json");
const DEFAULT_OUT = resolve(REPO_ROOT, "proposals/garak-clusters");
const BENIGN_CODE_DIR = resolve(REPO_ROOT, "data/benign-code");
const DEFAULT_MAX_TP = 40; // cap TPs per family proposal; the judge defines the class, it needn't see every literal
const MIN_TP = 2; // consumer requires >=2 true_positives; below this we skip the family

// ---------------------------------------------------------------------------
// Scope: agent-attack families (IN scope). MUST stay aligned with
// GARAK_FAMILY_ALLOW in scripts/author-semantic-rules.ts — these are the only
// families the T2 consumer will admit from the garak source.
// ---------------------------------------------------------------------------
const GARAK_FAMILY_ALLOW = new Set<string>([
  "dan", // DAN-style jailbreak personas = instruction override
  "latentinjection", // indirect / latent prompt injection
  "agent_breaker", // agent self-description / tool-enumeration probing
  "goodside", // canonical prompt-injection probes
  "sysprompt_extraction", // system-prompt / initialization extraction
  "encoding", // encoding-obfuscated injection
  "web_injection", // web / markdown injection
  "promptinject", // PromptInject corpus (not in this report, kept for parity)
  "exploitation", // injection-driven exploitation (e.g. SQLi via agent input)
]);

// Per-sample content-safety guard. Mirrors CONTENT_SAFETY_TERMS in
// author-semantic-rules.ts: drop any individual prompt that reads as
// content-policy harm even inside an allowed family.
const CONTENT_SAFETY_TERMS =
  /\b(napalm|lsd|methamphetamine|cocaine|heroin|dismember|gore|child\s+(porn|sexual)|csam|bioweapon|nerve\s+agent|sarin|anthrax|pipe\s+bomb|suicide\s+method|self[-\s]harm|ricin|mustard\s+gas)\b/i;

// ATR category per agent-attack family. Every value MUST be in the consumer's
// VALID_CATEGORIES set or the proposal is skipped at read time.
const FAMILY_CATEGORY: Record<string, string> = {
  dan: "prompt-injection",
  latentinjection: "prompt-injection",
  agent_breaker: "context-exfiltration", // probes for tools / purpose / system info
  goodside: "prompt-injection",
  sysprompt_extraction: "context-exfiltration", // extracts the system prompt / init string
  encoding: "prompt-injection",
  web_injection: "prompt-injection",
  promptinject: "prompt-injection",
  exploitation: "prompt-injection",
};

const FAMILY_SUBCATEGORY: Record<string, string> = {
  dan: "instruction-override",
  latentinjection: "indirect-injection",
  agent_breaker: "tool-enumeration",
  goodside: "direct-injection",
  sysprompt_extraction: "system-prompt-extraction",
  encoding: "encoding-obfuscation",
  web_injection: "markdown-injection",
  promptinject: "direct-injection",
  exploitation: "injection-exploitation",
};

const FAMILY_OWASP: Record<string, string[]> = {
  dan: ["LLM01:2025 - Prompt Injection"],
  latentinjection: ["LLM01:2025 - Prompt Injection"],
  agent_breaker: ["LLM07:2025 - System Prompt Leakage"],
  goodside: ["LLM01:2025 - Prompt Injection"],
  sysprompt_extraction: ["LLM07:2025 - System Prompt Leakage"],
  encoding: ["LLM01:2025 - Prompt Injection"],
  web_injection: ["LLM01:2025 - Prompt Injection"],
  promptinject: ["LLM01:2025 - Prompt Injection"],
  exploitation: ["LLM01:2025 - Prompt Injection"],
};

const FAMILY_ATLAS: Record<string, string[]> = {
  dan: ["AML.T0054 - LLM Jailbreak"],
  latentinjection: ["AML.T0051.001 - LLM Prompt Injection: Indirect"],
  agent_breaker: ["AML.T0057 - LLM Data Leakage"],
  goodside: ["AML.T0051.000 - LLM Prompt Injection: Direct"],
  sysprompt_extraction: ["AML.T0056 - Extract LLM System Prompt"],
  encoding: ["AML.T0051 - LLM Prompt Injection"],
  web_injection: ["AML.T0051.001 - LLM Prompt Injection: Indirect"],
  promptinject: ["AML.T0051.000 - LLM Prompt Injection: Direct"],
  exploitation: ["AML.T0051 - LLM Prompt Injection"],
};

// Fixed agent-context benign negatives, blended with the benign-code corpus so
// the proposal always carries true_negatives even if the corpus is unavailable.
const STATIC_BENIGN: string[] = [
  "What is the weather like today in Tokyo?",
  "Help me write a Python function to sort a list of integers.",
  "Can you explain how photosynthesis works?",
  "Summarize the attached quarterly report into three bullet points.",
  "Translate hello how are you into Spanish.",
  "What tools should I use to format a CSV file in pandas?",
];

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};
const WRITE = flag("--write");
const REPORT_PATH = resolve(opt("--report") ?? DEFAULT_REPORT);
const OUT_DIR = resolve(opt("--out") ?? DEFAULT_OUT);
const MAX_TP = opt("--max-tp") ? Math.max(MIN_TP, parseInt(opt("--max-tp")!, 10)) : DEFAULT_MAX_TP;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface MissedPrompt {
  family: string;
  promptIdx?: number;
  prompt: string;
}
interface FamilyStat {
  family: string;
  total: number;
  detected: number;
  missed: number;
  recall: number;
}
interface GarakReport {
  benchmark?: string;
  date?: string;
  grand_total?: number;
  grand_missed?: number;
  grand_recall?: number;
  by_family?: FamilyStat[];
  missed_prompts?: MissedPrompt[];
}

interface ManifestEntry {
  sha8: string;
  family: string;
  anchor: string;
  cluster_size: number;
  file: string;
  category: string;
}
interface SkippedEntry {
  family: string;
  reason: string;
  count: number;
}

// ---------------------------------------------------------------------------
// Helpers (pure, testable)
// ---------------------------------------------------------------------------

/** Stable 8-char id for a family cluster, derived from family + sorted TPs. */
export function clusterSha8(family: string, truePositives: string[]): string {
  const basis = family + " " + [...truePositives].sort().join(" ");
  return createHash("sha256").update(basis).digest("hex").slice(0, 8);
}

/** True if a prompt is in-scope: non-empty, allowed family, not content-safety. */
export function isAgentAttackPrompt(family: string, prompt: string): boolean {
  if (!GARAK_FAMILY_ALLOW.has(family)) return false;
  const t = (prompt ?? "").trim();
  if (t.length < 4) return false;
  if (CONTENT_SAFETY_TERMS.test(t)) return false;
  return true;
}

/**
 * Group a report's missed prompts into one in-scope cluster per agent family.
 * Deduplicates prompts within a family. Pure: no IO.
 */
export function clusterMisses(
  missed: MissedPrompt[],
): { clusters: Map<string, string[]>; skipped: Map<string, SkippedEntry> } {
  const clusters = new Map<string, string[]>();
  const seenPerFamily = new Map<string, Set<string>>();
  const skipped = new Map<string, SkippedEntry>();

  const bump = (family: string, reason: string) => {
    const key = `${family}:${reason}`;
    const cur = skipped.get(key);
    if (cur) skipped.set(key, { ...cur, count: cur.count + 1 });
    else skipped.set(key, { family, reason, count: 1 });
  };

  for (const m of missed) {
    const family = m.family;
    const t = (m.prompt ?? "").trim();
    if (!GARAK_FAMILY_ALLOW.has(family)) {
      bump(family, "out-of-scope family (content-safety / not an agent attack)");
      continue;
    }
    if (t.length < 4) {
      bump(family, "empty or degenerate prompt");
      continue;
    }
    if (CONTENT_SAFETY_TERMS.test(t)) {
      bump(family, "content-safety sample inside allowed family");
      continue;
    }
    let seen = seenPerFamily.get(family);
    if (!seen) {
      seen = new Set<string>();
      seenPerFamily.set(family, seen);
    }
    if (seen.has(t)) {
      bump(family, "duplicate prompt within family");
      continue;
    }
    seen.add(t);
    const arr = clusters.get(family) ?? [];
    arr.push(t);
    clusters.set(family, arr);
  }
  return { clusters, skipped };
}

/** Load the benign-code corpus texts (for true_negatives). */
function loadBenignCode(limit: number): string[] {
  if (!existsSync(BENIGN_CODE_DIR)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(BENIGN_CODE_DIR)) {
    if (!entry.endsWith(".jsonl")) continue;
    let raw: string;
    try {
      raw = readFileSync(join(BENIGN_CODE_DIR, entry), "utf-8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const o = JSON.parse(t) as { text?: string };
        if (typeof o.text === "string" && o.text.trim().length > 0) out.push(o.text.trim());
      } catch {
        /* skip */
      }
      if (out.length >= limit) break;
    }
    if (out.length >= limit) break;
  }
  return out;
}

function titleCase(family: string): string {
  return family
    .split(/[_\s]+/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/**
 * Build the proposal document for one family cluster. Shape MUST match what
 * author-semantic-rules.ts reads: tags.category (valid ATR category),
 * tags.source = "garak-probe-<family>", test_cases.true_positives[].input
 * (>=2), test_cases.true_negatives[].input, references.owasp_llm / mitre_atlas,
 * severity, title.
 */
export function buildProposalDoc(
  family: string,
  truePositives: string[],
  trueNegatives: string[],
  reportDate: string,
  id: string,
): Record<string, unknown> {
  const category = FAMILY_CATEGORY[family] ?? "prompt-injection";
  const subcategory = FAMILY_SUBCATEGORY[family] ?? "direct-injection";
  const tp = truePositives.map((input, i) => ({
    input,
    expected: "triggered",
    description: `garak-${family} missed-by-ATR sample ${i + 1}`,
  }));
  const tn = trueNegatives.map((input, i) => ({
    input,
    expected: "not_triggered",
    description: `benign negative ${i + 1}`,
  }));

  return {
    title: `Garak ${titleCase(family)} - agent attack missed by ATR`,
    id,
    rule_version: 1,
    status: "draft",
    description:
      `Detects the '${family}' garak agent-attack probe family. These ${truePositives.length} ` +
      `prompts are currently MISSED by ATR on the garak full benchmark and represent a ` +
      `semantic attack class (${subcategory}) that a T2 LLM-as-judge rule should cover. ` +
      `Sourced from data/garak-benchmark/garak-full-report.json (run ${reportDate}).`,
    author: "ATR Community (garak-miss-bridge)",
    date: reportDate,
    schema_version: "0.1",
    detection_tier: "semantic",
    maturity: "draft",
    severity: "medium",
    references: {
      owasp_llm: FAMILY_OWASP[family] ?? ["LLM01:2025 - Prompt Injection"],
      mitre_atlas: FAMILY_ATLAS[family] ?? ["AML.T0051 - LLM Prompt Injection"],
    },
    tags: {
      category,
      subcategory,
      scan_target: "llm_io",
      confidence: "medium",
      source: `garak-probe-${family}`,
    },
    agent_source: {
      type: "llm_io",
      framework: ["any"],
      provider: ["any"],
    },
    detection: {
      condition: "any",
      false_positives: [
        "Legitimate research, documentation, or red-team testing that references these patterns.",
        "Benign user requests that superficially resemble the probe wording.",
      ],
      conditions: [], // T2 consumer authors the narrow fallback + judge prompt
    },
    response: {
      actions: ["block_input", "alert"],
      auto_response_threshold: "medium",
    },
    confidence: 60,
    test_cases: {
      true_positives: tp,
      true_negatives: tn,
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main(): number {
  if (!existsSync(REPORT_PATH)) {
    console.error(`[fatal] garak report not found: ${REPORT_PATH}`);
    return 1;
  }
  let report: GarakReport;
  try {
    report = JSON.parse(readFileSync(REPORT_PATH, "utf-8")) as GarakReport;
  } catch (e) {
    console.error(`[fatal] cannot parse garak report: ${e}`);
    return 1;
  }
  const missed = Array.isArray(report.missed_prompts) ? report.missed_prompts : [];
  if (missed.length === 0) {
    console.error("[fatal] report has no missed_prompts array");
    return 1;
  }
  const reportDate = (report.date ?? new Date().toISOString().slice(0, 10)).slice(0, 10);

  console.log(`garak report: ${REPORT_PATH}`);
  console.log(
    `  grand_total=${report.grand_total ?? "?"} grand_missed=${report.grand_missed ?? missed.length} ` +
      `grand_recall=${report.grand_recall ?? "?"}% families=${report.by_family?.length ?? "?"}`,
  );

  const { clusters, skipped } = clusterMisses(missed);

  // Drop families below the consumer's >=2 TP floor.
  const eligible = [...clusters.entries()].filter(([, tps]) => tps.length >= MIN_TP);
  const tooSmall = [...clusters.entries()].filter(([, tps]) => tps.length < MIN_TP);

  if (eligible.length === 0) {
    console.error("[done] no in-scope agent-attack family with >=2 misses — nothing to write");
    return 2;
  }

  const benignCode = loadBenignCode(200);
  const negatives = [...STATIC_BENIGN, ...benignCode.slice(0, 6)];

  // Deterministic family order for stable output.
  eligible.sort((a, b) => a[0].localeCompare(b[0]));

  const manifest: ManifestEntry[] = [];
  let totalTps = 0;

  console.log(`\n=== in-scope agent-attack families (${eligible.length}) ===`);
  for (const [family, allTps] of eligible) {
    const tps = allTps.slice(0, MAX_TP);
    totalTps += tps.length;
    const sha8 = clusterSha8(family, tps);
    const id = `ATR-GARAK-${sha8}`;
    const fileAbs = join(OUT_DIR, `${id}.proposal.yaml`);
    const fileRel = fileAbs.slice(REPO_ROOT.length + 1);
    const doc = buildProposalDoc(family, tps, negatives, reportDate, id);
    const ymlOut = yaml.dump(doc, { lineWidth: 120, noRefs: true, quotingType: '"' });

    console.log(
      `  ${family.padEnd(22)} misses=${String(allTps.length).padStart(4)} ` +
        `tps_written=${String(tps.length).padStart(4)} -> ${id}.proposal.yaml ` +
        `(category=${FAMILY_CATEGORY[family]})`,
    );

    if (WRITE) {
      if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
      writeFileSync(fileAbs, ymlOut, "utf-8");
    }

    manifest.push({
      sha8,
      family,
      anchor: "family-cluster",
      cluster_size: allTps.length,
      file: fileRel, // repo-relative — NOT an absolute machine path
      category: FAMILY_CATEGORY[family] ?? "prompt-injection",
    });
  }

  // Aggregate skipped reasons for the manifest + console.
  const skippedArr = [...skipped.values()].sort((a, b) => b.count - a.count);

  const manifestDoc = {
    date: reportDate,
    generator: "scripts/garak-miss-to-proposals.ts",
    source_report: REPORT_PATH.slice(REPO_ROOT.length + 1),
    grand_total: report.grand_total ?? null,
    grand_missed: report.grand_missed ?? missed.length,
    total_inscope_agent_misses: [...clusters.values()].reduce((n, a) => n + a.length, 0),
    proposals_written: manifest.length,
    true_positives_written: totalTps,
    max_tp_per_family: MAX_TP,
    proposals: manifest,
    families_below_min_tp: tooSmall.map(([f, a]) => ({ family: f, misses: a.length })),
    skipped: skippedArr,
  };

  console.log(`\n=== skipped (aggregated) ===`);
  for (const s of skippedArr.slice(0, 12)) {
    console.log(`  ${s.family.padEnd(22)} x${String(s.count).padStart(5)}  ${s.reason}`);
  }
  if (skippedArr.length > 12) console.log(`  ... ${skippedArr.length - 12} more reasons`);

  if (WRITE) {
    if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(join(OUT_DIR, "cluster-manifest.json"), JSON.stringify(manifestDoc, null, 2) + "\n", "utf-8");
  }

  console.log(
    `\n${WRITE ? "WROTE" : "DRY-RUN (use --write)"}: ${manifest.length} proposals + manifest, ` +
      `${totalTps} true_positives across ${eligible.length} agent families.`,
  );
  console.log(`  output dir: ${OUT_DIR}`);
  console.log(`  consumed by: scripts/author-semantic-rules.ts --source garak`);
  return 0;
}

// Only run when invoked directly (so unit tests can import the pure helpers).
const INVOKED_DIRECTLY = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (INVOKED_DIRECTLY) {
  process.exit(main());
}
