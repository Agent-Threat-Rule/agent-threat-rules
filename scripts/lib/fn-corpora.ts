/**
 * fn-corpora.ts — the registry of raw material for rule production.
 *
 * WHAT THIS IS
 *
 * One entry per corpus that lives in this repository, carrying the four facts
 * a rule miner has to know before it reads a single sample:
 *
 *   1. WHERE the samples are, and how to turn the file into `{id, text}`.
 *   2. WHETHER the samples are labelled, and what the labels mean. A corpus
 *      with no labels cannot produce a recall number; it can only produce hit
 *      counts. `labelled: false` says so out loud instead of letting a caller
 *      divide by a denominator that does not exist.
 *   3. WHICH CHANNEL the sample travels through in production. This is the
 *      single most expensive thing to get wrong in this repository — a garak
 *      jailbreak prompt arrives as `llm_input` or `tool_response`, never as a
 *      SKILL.md, and scoring it through `engine.scanSkill()` credits a
 *      detection on a channel the payload never travels. See
 *      src/corpus-event.ts for the two shape sets and why they differ.
 *   4. WHETHER the corpus is usable raw material for AGENT threat rules at
 *      all. Several corpora here are content-safety benchmarks: they measure
 *      whether a model will write a bomb recipe, which is a model alignment
 *      question, not an agent security question. `usable: false` records that
 *      judgement with its reason so nobody re-discovers it by mining noise.
 *
 * ON `usable: false`
 *
 * It is not a claim that the corpus is bad. AdvBench, HarmBench and
 * JailbreakBench are good corpora for what they measure. It is a claim that
 * ATR's detection surface — agent tool calls, MCP exchanges, skill manifests,
 * prompt channels — does not intersect what they measure, so a "miss" against
 * them is not a detection gap and mining them produces rules that fire on
 * topic words. Recording that here keeps the miner from manufacturing work.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

/**
 * The production channel a sample travels through.
 *
 *   `prompt`   — raw adversarial text that reaches the agent as user input or
 *                as poisoned tool/RAG output. Scored on promptChannelShapes().
 *   `document` — an artifact the agent reads or installs (SKILL.md, manifest,
 *                source file). Scored on the full corpusShapes() + scanSkill().
 */
export type CorpusChannel = "prompt" | "document";

/** One sample, normalised. `family` is the corpus's own taxonomy, verbatim. */
export interface CorpusSample {
  readonly id: string;
  readonly text: string;
  readonly family: string;
  readonly label: "attack" | "benign" | "unlabelled";
}

export interface CorpusDef {
  readonly id: string;
  readonly channel: CorpusChannel;
  /** Relative to repo root. Existence of this path gates the loader. */
  readonly path: string;
  /** False when the corpus ships no attack/benign label per sample. */
  readonly labelled: boolean;
  /** False when the corpus does not measure anything ATR detects. */
  readonly usable: boolean;
  /** Why usable is false, or what the corpus contributes when it is true. */
  readonly note: string;
  readonly load: (root: string) => readonly CorpusSample[];
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

function readJson<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as T;
  } catch {
    return null;
  }
}

function trimmed(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/** Drop samples too short to carry an artifact; they only inflate denominators. */
const MIN_SAMPLE_CHARS = 12;

function keep(text: string): boolean {
  return text.length >= MIN_SAMPLE_CHARS;
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

interface GarakFamilyFile {
  readonly family?: string;
  readonly prompts?: readonly string[];
}

function loadGarakFull(root: string): readonly CorpusSample[] {
  const dir = join(root, "data/test-corpora/garak-full");
  if (!existsSync(dir)) return [];
  const out: CorpusSample[] = [];
  for (const entry of readdirSync(dir).sort()) {
    if (!entry.endsWith(".json")) continue;
    const file = readJson<GarakFamilyFile>(join(dir, entry));
    const family = file?.family ?? entry.replace(/\.json$/, "");
    for (const [i, prompt] of (file?.prompts ?? []).entries()) {
      const text = trimmed(prompt);
      if (!keep(text)) continue;
      out.push({ id: `garak-${family}-${i}`, text, family, label: "attack" });
    }
  }
  return out;
}

interface PintRow {
  readonly text?: string;
  readonly category?: string;
  readonly label?: boolean;
}

function loadPint(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly PintRow[]>(join(root, "data/pint-benchmark/pint-corpus.json"));
  if (rows === null) return [];
  return rows.flatMap((row, i) => {
    const text = trimmed(row.text);
    if (!keep(text)) return [];
    return [
      {
        id: `pint-${i}`,
        text,
        family: row.category ?? "unknown",
        label: row.label === true ? ("attack" as const) : ("benign" as const),
      },
    ];
  });
}

interface AttackFixture {
  readonly text?: string;
  readonly attack_family?: string;
}

/** llm-guard / nemo-guardrails / promptfoo all ship this one schema. */
function loadAttackFixtures(relPath: string, prefix: string) {
  return (root: string): readonly CorpusSample[] => {
    const file = readJson<{ attacks?: readonly AttackFixture[] }>(join(root, relPath));
    return (file?.attacks ?? []).flatMap((a, i) => {
      const text = trimmed(a.text);
      if (!keep(text)) return [];
      return [
        {
          id: `${prefix}-${i}`,
          text,
          family: a.attack_family ?? "unknown",
          label: "attack" as const,
        },
      ];
    });
  };
}

interface HhRlhfRow {
  readonly idx?: number;
  readonly first_human_turn?: string;
  readonly task_description?: string;
}

function loadHhRlhf(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly HhRlhfRow[]>(join(root, "data/test-corpora/hh-rlhf/sample-5000.json"));
  if (rows === null) return [];
  return rows.flatMap((r, i) => {
    const text = trimmed(r.first_human_turn);
    if (!keep(text)) return [];
    return [
      {
        id: `hh-rlhf-${r.idx ?? i}`,
        text,
        family: trimmed(r.task_description) || "red-team-attempt",
        label: "attack" as const,
      },
    ];
  });
}

interface AtlasRow {
  readonly source_id?: string;
  readonly attack_description?: string;
  readonly attack_family?: string;
}

function loadAtlas(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly AtlasRow[]>(
    join(root, "data/test-corpora/mitre-atlas/attack-procedures.json"),
  );
  if (rows === null) return [];
  return rows.flatMap((r, i) => {
    const text = trimmed(r.attack_description);
    if (!keep(text)) return [];
    return [
      {
        id: `atlas-${r.source_id ?? "x"}-${i}`,
        text,
        family: r.attack_family ?? "unknown",
        label: "attack" as const,
      },
    ];
  });
}

interface OwaspVuln {
  readonly vuln_id?: string;
  readonly attack_scenarios?: readonly { readonly text?: string }[];
}

function loadOwasp(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly OwaspVuln[]>(
    join(root, "data/test-corpora/owasp-llm-top10/attack-scenarios.json"),
  );
  if (rows === null) return [];
  const out: CorpusSample[] = [];
  for (const vuln of rows) {
    for (const [i, scenario] of (vuln.attack_scenarios ?? []).entries()) {
      const text = trimmed(scenario.text);
      if (!keep(text)) continue;
      out.push({
        id: `owasp-${vuln.vuln_id ?? "x"}-${i}`,
        text,
        family: vuln.vuln_id ?? "unknown",
        label: "attack",
      });
    }
  }
  return out;
}

interface PromptbenchRow {
  readonly attack_type?: string;
  readonly attacked?: string;
}

function loadPromptbench(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly PromptbenchRow[]>(
    join(root, "data/test-corpora/promptbench/all.json"),
  );
  if (rows === null) return [];
  return rows.flatMap((r, i) => {
    const text = trimmed(r.attacked);
    if (!keep(text)) return [];
    return [
      { id: `promptbench-${i}`, text, family: r.attack_type ?? "unknown", label: "attack" as const },
    ];
  });
}

interface PromptinjectRow {
  readonly attack_class?: string;
  readonly full_prompt?: string;
}

function loadPromptinject(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly PromptinjectRow[]>(
    join(root, "data/test-corpora/promptinject/all.json"),
  );
  if (rows === null) return [];
  return rows.flatMap((r, i) => {
    const text = trimmed(r.full_prompt);
    if (!keep(text)) return [];
    return [
      {
        id: `promptinject-${i}`,
        text,
        family: r.attack_class ?? "unknown",
        label: "attack" as const,
      },
    ];
  });
}

interface AutoresearchRow {
  readonly payload?: string;
  readonly technique?: string;
}

function loadAutoresearch(relPath: string, prefix: string) {
  return (root: string): readonly CorpusSample[] => {
    const rows = readJson<readonly AutoresearchRow[]>(join(root, relPath));
    if (rows === null) return [];
    return rows.flatMap((r, i) => {
      const text = trimmed(r.payload);
      if (!keep(text)) return [];
      return [
        {
          id: `${prefix}-${i}`,
          text,
          family: r.technique ?? "unknown",
          label: "attack" as const,
        },
      ];
    });
  };
}

interface HackapromptRow {
  readonly text?: string;
  readonly category?: string;
  readonly label?: boolean;
}

function loadHackaprompt(root: string): readonly CorpusSample[] {
  const rows = readJson<readonly HackapromptRow[]>(
    join(root, "data/hackaprompt/hackaprompt-corpus.json"),
  );
  if (rows === null) return [];
  return rows.flatMap((r, i) => {
    const text = trimmed(r.text);
    if (!keep(text)) return [];
    return [
      {
        id: `hackaprompt-${i}`,
        text,
        family: r.category ?? "unknown",
        label: r.label === false ? ("benign" as const) : ("attack" as const),
      },
    ];
  });
}

interface ProposalShell {
  readonly id?: string;
  readonly test_cases?: {
    readonly true_positives?: readonly { readonly input?: string }[];
  };
  readonly tags?: { readonly subcategory?: string };
}

/**
 * AdvBench / HarmBench / JailbreakBench were imported into this repo as
 * DRAFT rule proposals, one YAML per upstream behaviour, with the raw prompt
 * parked in `test_cases.true_positives[0].input`. The proposals themselves
 * have empty `detection.conditions`; the only real content is that prompt.
 */
function loadProposalPrompts(relDir: string, prefix: string) {
  return (root: string): readonly CorpusSample[] => {
    const dir = join(root, relDir);
    if (!existsSync(dir)) return [];
    const out: CorpusSample[] = [];
    for (const entry of readdirSync(dir).sort()) {
      if (!entry.endsWith(".yaml") && !entry.endsWith(".yml")) continue;
      let shell: ProposalShell | null = null;
      try {
        shell = yaml.load(readFileSync(join(dir, entry), "utf-8")) as ProposalShell;
      } catch {
        continue;
      }
      const text = trimmed(shell?.test_cases?.true_positives?.[0]?.input);
      if (!keep(text)) continue;
      out.push({
        id: shell?.id ?? `${prefix}-${entry}`,
        text,
        family: shell?.tags?.subcategory ?? prefix,
        label: "attack",
      });
    }
    return out;
  };
}

function loadSkillBenchmarkMalicious(root: string): readonly CorpusSample[] {
  const dir = join(root, "data/skill-benchmark/malicious");
  if (!existsSync(dir)) return [];
  const out: CorpusSample[] = [];
  for (const entry of readdirSync(dir).sort()) {
    if (!entry.endsWith(".md")) continue;
    const text = readFileSync(join(dir, entry), "utf-8");
    if (!keep(text)) continue;
    out.push({
      id: entry.replace(/\.md$/, ""),
      text,
      family: entry.replace(/^adv-\d+-/, "").replace(/\.md$/, ""),
      label: "attack",
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

export const CORPORA: readonly CorpusDef[] = Object.freeze([
  {
    id: "garak-full",
    channel: "prompt",
    path: "data/test-corpora/garak-full",
    labelled: true,
    usable: true,
    note: "NVIDIA garak probe payloads, 23 families. Machine-generated adversarial suffixes, encodings and DAN variants — the densest artifact-bearing prompt corpus in the repo.",
    load: loadGarakFull,
  },
  {
    id: "pint",
    channel: "prompt",
    path: "data/pint-benchmark/pint-corpus.json",
    labelled: true,
    usable: true,
    note: "Self-built 850-sample set, NOT Lakera's official PINT. Mixed attack/benign, so it is the only in-repo prompt corpus that can produce a precision number as well as a recall number.",
    load: loadPint,
  },
  {
    id: "hackaprompt",
    channel: "prompt",
    path: "data/hackaprompt/hackaprompt-corpus.json",
    labelled: true,
    usable: true,
    note: "HackAPrompt competition submissions. GITIGNORED — present only on a machine that ran scripts/hackaprompt-to-corpus.py. Human-written injections against a fixed target prompt.",
    load: loadHackaprompt,
  },
  {
    id: "llm-guard",
    channel: "prompt",
    path: "data/test-corpora/llm-guard/corpus.json",
    labelled: true,
    usable: true,
    note: "Protect AI llm-guard input-scanner fixtures.",
    load: loadAttackFixtures("data/test-corpora/llm-guard/corpus.json", "llm-guard"),
  },
  {
    id: "nemo-guardrails",
    channel: "prompt",
    path: "data/test-corpora/nemo-guardrails/corpus.json",
    labelled: true,
    usable: true,
    note: "NVIDIA NeMo Guardrails red-team fixtures.",
    load: loadAttackFixtures("data/test-corpora/nemo-guardrails/corpus.json", "nemo"),
  },
  {
    id: "promptfoo",
    channel: "prompt",
    path: "data/test-corpora/promptfoo/corpus.json",
    labelled: true,
    usable: true,
    note: "promptfoo red-team plugin fixtures.",
    load: loadAttackFixtures("data/test-corpora/promptfoo/corpus.json", "promptfoo"),
  },
  {
    id: "promptinject",
    channel: "prompt",
    path: "data/test-corpora/promptinject/all.json",
    labelled: true,
    usable: true,
    note: "PromptInject goal-hijacking / prompt-leaking grid. Templated: a small set of rogue strings crossed with delimiters and escapes, so distinct techniques are far fewer than the row count.",
    load: loadPromptinject,
  },
  {
    id: "autoresearch-adversarial",
    channel: "prompt",
    path: "data/autoresearch/adversarial-samples.json",
    labelled: true,
    usable: true,
    note: "Mutations of ATR's OWN rule true-positives. Useful for evasion hardening of an existing rule; circular as evidence of coverage, because every sample descends from a pattern ATR already ships.",
    load: loadAutoresearch("data/autoresearch/adversarial-samples.json", "autoresearch"),
  },
  {
    id: "autoresearch-missed",
    channel: "prompt",
    path: "data/autoresearch/missed-payloads.json",
    labelled: true,
    usable: true,
    note: "The subset of the above that evaded its parent rule at generation time. Same circularity caveat.",
    load: loadAutoresearch("data/autoresearch/missed-payloads.json", "autoresearch-missed"),
  },
  {
    id: "skill-benchmark-malicious",
    channel: "document",
    path: "data/skill-benchmark/malicious",
    labelled: true,
    usable: true,
    note: "Hand-authored malicious SKILL.md files. The only in-repo corpus on the document channel, and the only one whose samples are shaped like what `pga scan` actually reads.",
    load: loadSkillBenchmarkMalicious,
  },
  {
    id: "mitre-atlas",
    channel: "prompt",
    path: "data/test-corpora/mitre-atlas/attack-procedures.json",
    labelled: true,
    usable: false,
    note: "PROSE ABOUT attacks, not attack payloads: case-study narrative extracted from ATLAS write-ups. A rule mined from it detects incident-report English, which is the exact defect that retired the ATR-PRED-* batch.",
    load: loadAtlas,
  },
  {
    id: "owasp-llm-top10",
    channel: "prompt",
    path: "data/test-corpora/owasp-llm-top10/attack-scenarios.json",
    labelled: true,
    usable: false,
    note: "Same defect as mitre-atlas: 'Example Attack Scenario' paragraphs from the OWASP document. Descriptive prose, no payload.",
    load: loadOwasp,
  },
  {
    id: "hh-rlhf",
    channel: "prompt",
    path: "data/test-corpora/hh-rlhf/sample-5000.json",
    labelled: true,
    usable: false,
    note: "Anthropic red-team dialogue openers. Content-safety, not agent security — the target is what the model says, not what an agent does. Mining it yields topic-word rules.",
    load: loadHhRlhf,
  },
  {
    id: "advbench",
    channel: "prompt",
    path: "data/test-corpora/advbench",
    labelled: true,
    usable: false,
    note: "Harmful-behaviour instructions ('write a tutorial on ...'). Content-safety benchmark; ATR has no detection surface for it.",
    load: loadProposalPrompts("data/test-corpora/advbench", "advbench"),
  },
  {
    id: "harmbench",
    channel: "prompt",
    path: "data/test-corpora/harmbench",
    labelled: true,
    usable: false,
    note: "Same class as advbench, plus copyright-reproduction prompts.",
    load: loadProposalPrompts("data/test-corpora/harmbench", "harmbench"),
  },
  {
    id: "jailbreakbench",
    channel: "prompt",
    path: "data/test-corpora/jailbreakbench",
    labelled: true,
    usable: false,
    note: "Same class as advbench. 100 behaviours, no payload obfuscation.",
    load: loadProposalPrompts("data/test-corpora/jailbreakbench", "jailbreakbench"),
  },
  {
    id: "promptbench",
    channel: "prompt",
    path: "data/test-corpora/promptbench/all.json",
    labelled: true,
    usable: false,
    note: "Adversarial ROBUSTNESS perturbations (typos, synonym swaps, distractor sentences) of benign NLP task prompts. The samples are not attacks on an agent; a rule that fires on them fires on misspelled English.",
    load: loadPromptbench,
  },
]);

export function corpusById(id: string): CorpusDef | undefined {
  return CORPORA.find((c) => c.id === id);
}

export function corpusIds(): readonly string[] {
  return CORPORA.map((c) => c.id);
}
