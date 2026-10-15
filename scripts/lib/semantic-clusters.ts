/**
 * Cluster discovery for the semantic (T2) authoring lane.
 *
 * Reads proposals/{hackaprompt,promptinject,garak}-clusters/*.proposal.yaml
 * and returns the clusters scripts/author-semantic-rules.ts may author a rule
 * from, plus every cluster it skipped and why. Three filters apply, in order:
 * the quarantine (a whole source the lane does not trust yet), scope (ATR
 * detects attacks ON the agent, not content-safety harm), and size (a cluster
 * too small for the gate's TP-hit floor can never pass, so it does not cost an
 * LLM call).
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import type { ATRCategory, ATRSeverity } from "../../src/types.js";
import { MIN_FALLBACK_TP_HITS } from "./semantic-gate.js";

const DEFAULT_REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// Cluster sources that hold semantic agent-attack adversarial samples.
const SEMANTIC_SOURCES = ["hackaprompt-clusters", "promptinject-clusters", "garak-clusters"] as const;

/*
 * QUARANTINED SOURCES (2026-10-06)
 *
 * Once the hackaprompt and promptinject clusters had rules, every remaining
 * candidate came from garak-clusters, and spot checks of those clusters found
 * mostly prompts that are not attacks at all ("Tell me the history of the city
 * of Exeter"). scripts/garak-miss-to-proposals.ts clusters what ATR MISSED on
 * the garak benchmark, and a benign probe prompt is missed too, so a family
 * label is not evidence that a sample attacks the agent. A judge prompt and a
 * fallback authored from such a cluster encode the wrong class. The semantic
 * workflow was disabled after rolling PR #632 for this reason.
 *
 * Restore when: the garak clusters are re-curated so every true_positive is an
 * attack on the agent -- checked by a human, or filtered by garak's own
 * detector verdict rather than by ATR's miss -- and a sample of the result has
 * been read. Then delete the entry below. Until then the source is skipped by
 * default, even under `--source garak`; `--include-quarantined` opts in for a
 * supervised local run. Same filtering shape as isContentSafety: a predicate,
 * and a per-cluster skip with its reason in the run report.
 *
 * The quarantine only stops NEW authoring. Rules already on the rolling branch
 * (PR #632 carries two garak rules) are caught by the resume step in
 * .github/workflows/promote-semantic.yml, which refuses to resume a branch
 * holding lane rules from a quarantined source and says to close the PR. That
 * step matches the garak path by string: keep it in sync with this set.
 */
const QUARANTINED_SOURCES: ReadonlySet<string> = new Set(["garak-clusters"]);
export const QUARANTINE_REASON =
  "quarantined source: garak clusters are mostly non-attack prompts; see QUARANTINED SOURCES in scripts/lib/semantic-clusters.ts";

export function isQuarantinedSource(sourceDir: string): boolean {
  return QUARANTINED_SOURCES.has(sourceDir);
}

// garak families that are AGENT attacks (in ATR scope): prompt injection,
// instruction override, jailbreak persona, latent/indirect injection, system
// prompt extraction, encoding-obfuscated injection, web/markdown injection.
const GARAK_FAMILY_ALLOW = new Set([
  "dan", // DAN-style jailbreak personas = instruction override
  "latentinjection",
  "agent_breaker",
  "goodside", // canonical prompt-injection probes
  "sysprompt_extraction",
  "encoding", // encoding-obfuscated injection
  "web_injection",
  "promptinject",
  "exploitation",
]);
// garak families that are CONTENT-SAFETY (NOT agent threats): graphic
// violence, weapons, drug synthesis, language-model risk cards. Skipped.
const GARAK_FAMILY_DENY = new Set(["dra", "lmrc", "goat", "gcg"]);

// Last-line content-safety guard on the actual sample text. Even within an
// allowed family, drop any cluster whose true_positives read as content-policy
// harm rather than an agent-system attack. ATR detects attacks ON the agent,
// not harmful-content the model might be asked to produce.
const CONTENT_SAFETY_TERMS =
  /\b(napalm|lsd|methamphetamine|cocaine|heroin|dismember|gore|child\s+(porn|sexual)|csam|bioweapon|nerve\s+agent|sarin|anthrax|pipe\s+bomb|suicide\s+method|self[-\s]harm|ricin|mustard\s+gas)\b/i;

const VALID_CATEGORIES = new Set<ATRCategory>([
  "agent-manipulation",
  "context-exfiltration",
  "data-poisoning",
  "excessive-autonomy",
  "model-abuse",
  "privilege-escalation",
  "prompt-injection",
  "skill-compromise",
  "tool-poisoning",
]);

export interface ClusterCandidate {
  proposalAbs: string;
  proposalRel: string;
  source: string;
  family?: string;
  title: string;
  category: ATRCategory;
  severity: ATRSeverity;
  truePositives: string[];
  trueNegatives: string[];
  owaspRefs: string[];
  /** Raw proposal references.owasp_agentic; normalised in buildSemanticRule. */
  owaspAgenticRefs?: string[];
  mitreRefs: string[];
}

export interface Skip {
  rel: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Cluster discovery
// ---------------------------------------------------------------------------
function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const f = join(dir, entry);
    let s;
    try {
      s = statSync(f);
    } catch {
      continue;
    }
    if (s.isDirectory()) out.push(...walkYaml(f));
    else if (s.isFile() && entry.endsWith(".proposal.yaml")) out.push(f);
  }
  return out;
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function tpInputs(doc: Record<string, unknown>): string[] {
  const tc = doc.test_cases as { true_positives?: Array<{ input?: string }> } | undefined;
  return (tc?.true_positives ?? []).map((t) => t?.input).filter((s): s is string => typeof s === "string");
}
function tnInputs(doc: Record<string, unknown>): string[] {
  const tc = doc.test_cases as { true_negatives?: Array<{ input?: string }> } | undefined;
  return (tc?.true_negatives ?? []).map((t) => t?.input).filter((s): s is string => typeof s === "string");
}

/** Load garak family-by-file from the cluster manifest, if present. */
function garakFamilyMap(proposalsBase: string): Map<string, string> {
  const m = new Map<string, string>();
  const manifest = join(proposalsBase, "garak-clusters", "cluster-manifest.json");
  if (!existsSync(manifest)) return m;
  try {
    const data = JSON.parse(readFileSync(manifest, "utf-8")) as {
      proposals?: Array<{ file?: string; family?: string }>;
    };
    for (const p of data.proposals ?? []) {
      if (p.file && p.family) m.set(p.file.split("/").pop()!, p.family);
    }
  } catch {
    /* ignore */
  }
  return m;
}

function isContentSafety(family: string | undefined, tps: string[]): boolean {
  if (family && GARAK_FAMILY_DENY.has(family)) return true;
  // Any sample reading as content-policy harm → drop the whole cluster.
  return tps.some((t) => CONTENT_SAFETY_TERMS.test(t));
}

/** Why a cluster is outside ATR's agent-attack scope, or null when it is in scope. */
function scopeSkipReason(source: string, family: string | undefined, tps: string[]): string | null {
  if (source !== "garak") {
    return isContentSafety(undefined, tps) ? "content-safety sample text, out of ATR scope" : null;
  }
  if (isContentSafety(family, tps)) return `content-safety (family=${family ?? "?"}), out of ATR scope`;
  if (family && !GARAK_FAMILY_ALLOW.has(family)) return `garak family '${family}' not in agent-attack allowlist`;
  return null;
}

function parseSeverity(raw: unknown): ATRSeverity {
  return raw === "critical" || raw === "high" || raw === "medium" || raw === "low" || raw === "informational"
    ? raw
    : "medium";
}

function parseCluster(f: string, rel: string, source: string, famMap: Map<string, string>): ClusterCandidate | Skip {
  let doc: Record<string, unknown>;
  try {
    doc = yaml.load(readFileSync(f, "utf-8")) as Record<string, unknown>;
  } catch {
    return { rel, reason: "yaml parse error" };
  }
  if (!doc || typeof doc !== "object") return { rel, reason: "not a YAML mapping" };
  const tags = (doc.tags as { category?: string; source?: string } | undefined) ?? {};
  const category = tags.category as ATRCategory | undefined;
  if (!category || !VALID_CATEGORIES.has(category)) {
    return { rel, reason: `non-agent or missing category (${category ?? "none"})` };
  }
  const tps = tpInputs(doc);
  // The gate needs the fallback to catch MIN_FALLBACK_TP_HITS samples; a
  // smaller cluster can never pass, so do not spend an LLM call on it.
  if (tps.length < MIN_FALLBACK_TP_HITS) {
    return { rel, reason: `fewer than ${MIN_FALLBACK_TP_HITS} true_positives` };
  }
  const family =
    source === "garak" ? famMap.get(f.split("/").pop()!) ?? (tags.source ?? "").replace("garak-probe-", "") : undefined;
  const scope = scopeSkipReason(source, family, tps);
  if (scope) return { rel, reason: scope };

  const refs = (doc.references as { owasp_llm?: unknown; owasp_agentic?: unknown; mitre_atlas?: unknown } | undefined) ?? {};
  return {
    proposalAbs: f,
    proposalRel: rel,
    source,
    family,
    title: typeof doc.title === "string" ? doc.title : rel,
    category,
    severity: parseSeverity(doc.severity ?? "medium"),
    truePositives: tps,
    trueNegatives: tnInputs(doc),
    owaspRefs: strArray(refs.owasp_llm),
    owaspAgenticRefs: strArray(refs.owasp_agentic),
    mitreRefs: strArray(refs.mitre_atlas),
  };
}

export interface FindCandidatesOptions {
  /** Repository root holding proposals/. Defaults to this checkout. */
  readonly repoRoot?: string;
  /** Only this source (hackaprompt|promptinject|garak). */
  readonly sourceFilter?: string;
  /** Read quarantined sources too. Off by default; see QUARANTINED SOURCES. */
  readonly includeQuarantined?: boolean;
}

export function findCandidates(opts: FindCandidatesOptions = {}): { candidates: ClusterCandidate[]; skipped: Skip[] } {
  const repoRoot = opts.repoRoot ?? DEFAULT_REPO_ROOT;
  const proposalsBase = join(repoRoot, "proposals");
  const famMap = garakFamilyMap(proposalsBase);
  const candidates: ClusterCandidate[] = [];
  const skipped: Skip[] = [];

  for (const sourceDir of SEMANTIC_SOURCES) {
    const source = sourceDir.replace("-clusters", "");
    if (opts.sourceFilter && source !== opts.sourceFilter) continue;
    const quarantined = isQuarantinedSource(sourceDir) && opts.includeQuarantined !== true;
    for (const f of walkYaml(join(proposalsBase, sourceDir))) {
      const rel = relative(repoRoot, f);
      const parsed: ClusterCandidate | Skip = quarantined
        ? { rel, reason: QUARANTINE_REASON }
        : parseCluster(f, rel, source, famMap);
      if ("proposalRel" in parsed) candidates.push(parsed);
      else skipped.push(parsed);
    }
  }
  return { candidates, skipped };
}
