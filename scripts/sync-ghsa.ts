#!/usr/bin/env npx tsx
/**
 * sync-ghsa.ts
 *
 * Pulls GitHub Security Advisories (GHSA) for AI / agent / LLM / MCP
 * ecosystem packages and emits ATR rule proposals under
 * proposals/ghsa/<GHSA-ID>.proposal.yaml.
 *
 * GHSA is the largest practical source of AI package CVEs because most
 * vulnerable LangChain / LlamaIndex / vLLM / mcp-* packages publish their
 * advisory there before / instead of NVD. The advisory body usually
 * includes a reproducer or PoC URL, which is what makes a CVE
 * "detection-ready" from ATR's point of view.
 *
 * Filter strategy:
 *  - Iterate an AI-package allowlist per ecosystem (pip / npm / maven /
 *    nuget / go / rubygems)
 *  - For each (ecosystem, package), fetch advisories via
 *    GET /advisories?ecosystem=...&affects=...
 *  - Skip advisories that are withdrawn
 *  - Skip advisories whose CVE id is already covered in rules/ or in any
 *    other proposals/ subtree
 *
 * Detection-readiness triage:
 *  - The proposal is written with empty detection.conditions (same as
 *    sync-cisa-kev.ts). A `_triage.detection_ready` field is set to
 *    `true` only when the advisory body contains a clearly extractable
 *    payload (e.g. fenced code block with attack input, "Proof of
 *    Concept" section, "Reproducer" header). Otherwise
 *    `detection_ready: false` and the proposal is tracking-only.
 *
 * Auth:
 *  - GITHUB_TOKEN env var optional; without it the script runs at the
 *    60-req/hour unauthenticated limit and will exit cleanly if rate
 *    limited.
 *
 * Usage:
 *   npx tsx scripts/sync-ghsa.ts                  # dry-run, all ecosystems
 *   npx tsx scripts/sync-ghsa.ts --write          # write proposals
 *   npx tsx scripts/sync-ghsa.ts --ecosystem pip  # one ecosystem
 *   npx tsx scripts/sync-ghsa.ts --since 2026-04  # only entries >= date
 *   npx tsx scripts/sync-ghsa.ts --advisory GHSA-xxxx-yyyy-zzzz
 *   npx tsx scripts/sync-ghsa.ts --limit 50       # cap output
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 rate-limited (recoverable; daily cron will retry tomorrow)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "ghsa");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const SINCE = opt("--since");
const ECOSYSTEM_FILTER = opt("--ecosystem");
const ADVISORY_FILTER = opt("--advisory");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;
const VERBOSE = flag("--verbose");

// AI / agent / LLM / MCP package allowlist by ecosystem.
// Keep this curated — broad "matches /ai/" globs drag in unrelated CVEs.
const AI_PACKAGES: Record<string, string[]> = {
  pip: [
    "langchain",
    "langchain-core",
    "langchain-community",
    "langchain-experimental",
    "langgraph",
    "langsmith",
    "llama-index",
    "llama-index-core",
    "openai",
    "anthropic",
    "transformers",
    "vllm",
    "mlflow",
    "ray",
    "gradio",
    "dspy",
    "dspy-ai",
    "autogen-agentchat",
    "pyautogen",
    "crewai",
    "litellm",
    "semantic-kernel",
    "pyrit",
    "garak",
    "promptfoo",
    "llm-guard",
    "nemoguardrails",
    "guardrails-ai",
    "pydantic-ai",
    "haystack-ai",
    "instructor",
    "ollama",
    "embedchain",
    "mcp",
    "fastmcp",
    "huggingface-hub",
    "diffusers",
    "accelerate",
    "datasets",
    "torch",
    "tensorflow",
    "onnxruntime",
  ],
  npm: [
    "@langchain/core",
    "@langchain/community",
    "@langchain/openai",
    "@langchain/anthropic",
    "langchain",
    "openai",
    "@anthropic-ai/sdk",
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/inspector",
    "ai",
    "@vercel/ai",
    "@ai-sdk/openai",
    "@ai-sdk/anthropic",
    "llamaindex",
    "ollama",
    "@google/genai",
    "@aws-sdk/client-bedrock-runtime",
  ],
  maven: [
    "dev.langchain4j:langchain4j",
    "com.theokanning.openai-gpt3-java:api",
  ],
  nuget: ["Microsoft.SemanticKernel", "OpenAI"],
  go: ["github.com/tmc/langchaingo", "github.com/sashabaranov/go-openai"],
  rubygems: ["langchainrb", "ruby-openai", "anthropic"],
};

// CWE → ATR category (subset of mapping in sync-cisa-kev.ts).
const CWE_TO_CATEGORY: Record<string, string> = {
  "CWE-94": "model-abuse",
  "CWE-78": "tool-poisoning",
  "CWE-89": "data-poisoning",
  "CWE-77": "tool-poisoning",
  "CWE-79": "context-exfiltration",
  "CWE-22": "context-exfiltration",
  "CWE-918": "tool-poisoning",
  "CWE-502": "model-abuse",
  "CWE-611": "context-exfiltration",
  "CWE-200": "context-exfiltration",
  "CWE-20": "prompt-injection",
  "CWE-863": "privilege-escalation",
  "CWE-862": "privilege-escalation",
  "CWE-601": "tool-poisoning",
  "CWE-1336": "prompt-injection",
};

function guessCategory(cwes: string[]): string {
  for (const c of cwes) {
    if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  }
  return "model-abuse";
}

interface GhsaPackage {
  ecosystem: string;
  name: string;
}
interface GhsaVulnerability {
  package: GhsaPackage;
  patched_versions?: string;
  vulnerable_version_range?: string;
}
interface GhsaAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  url: string;
  html_url: string;
  summary: string;
  description: string;
  severity: string;
  cwes?: Array<{ cwe_id: string; name: string }>;
  references: string[];
  vulnerabilities: GhsaVulnerability[];
  published_at: string;
  withdrawn_at?: string | null;
}

const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

async function ghsaFetch(
  ecosystem: string,
  pkg: string,
): Promise<GhsaAdvisory[]> {
  const u = new URL("https://api.github.com/advisories");
  u.searchParams.set("ecosystem", ecosystem);
  u.searchParams.set("affects", pkg);
  u.searchParams.set("per_page", "100");
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "atr-sync-ghsa",
  };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;

  const resp = await fetch(u.toString(), { headers });
  if (resp.status === 403 || resp.status === 429) {
    const remaining = resp.headers.get("x-ratelimit-remaining");
    const reset = resp.headers.get("x-ratelimit-reset");
    console.error(
      `rate limited on ${ecosystem}/${pkg}: remaining=${remaining}, reset=${reset}`,
    );
    process.exit(2);
  }
  if (!resp.ok) {
    if (VERBOSE)
      console.error(
        `non-200 for ${ecosystem}/${pkg}: ${resp.status} ${resp.statusText}`,
      );
    return [];
  }
  return (await resp.json()) as GhsaAdvisory[];
}

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    const st = statSync(f);
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

function buildKnownIndex(): { cves: Set<string>; ghsas: Set<string> } {
  const cves = new Set<string>();
  const ghsas = new Set<string>();
  const dirs = [RULES_DIR, PROPOSALS_BASE];
  for (const dir of dirs) {
    for (const f of walkYaml(dir)) {
      let raw: string;
      try {
        raw = readFileSync(f, "utf-8");
      } catch {
        continue;
      }
      let doc: unknown;
      try {
        doc = yaml.load(raw);
      } catch {
        continue;
      }
      const refs = (doc as { references?: { cve?: string[]; ghsa?: string[] } })
        ?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.ghsa)
        for (const g of refs.ghsa) if (typeof g === "string") ghsas.add(g);
    }
  }
  return { cves, ghsas };
}

const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "## *Proof of Concept",
    "## *Reproducer",
    "## *Exploit",
    "payload:",
    "curl ",
    "POST \\/[a-z]",
    "<script>",
    "prompt: ['\"]",
  ].join("|"),
  "im",
);

function isDetectionReady(adv: GhsaAdvisory): {
  ready: boolean;
  reason: string;
} {
  const body = `${adv.summary}\n${adv.description}`;
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return { ready: true, reason: "payload-like content in advisory body" };
  if (adv.references.some((r) => /poc|exploit-db|cve\.org/.test(r)))
    return { ready: true, reason: "PoC reference link present" };
  return {
    ready: false,
    reason: "advisory body has no reproducer / payload section",
  };
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\w]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

const ADVISORY_BODY_MAX_CHARS = 8000;

// Indent every line for embedding under a YAML `|` literal block.
// Empty lines also get the indent prefix so all parsers stay inside the block.
function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see html_url for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(adv: GhsaAdvisory): string {
  const cwes = (adv.cwes ?? []).map((c) => c.cwe_id);
  const category = guessCategory(cwes);
  const cveId = adv.cve_id ?? null;
  const draftIdSuffix = cveId
    ? cveId.replace(/^CVE-/, "")
    : adv.ghsa_id.replace(/^GHSA-/, "GHSA-");
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");

  const pkgList = adv.vulnerabilities.map(
    (v) => `${v.package.ecosystem}:${v.package.name}`,
  );
  const refExternal = adv.references.filter(
    (r): r is string => typeof r === "string" && r.length > 0,
  );

  const triage = isDetectionReady(adv);

  const cveBlock = cveId ? `  cve:\n    - "${cveId}"\n` : "";
  const cweBlock =
    cwes.length > 0
      ? `  cwe:\n${cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const ghsaBlock = `  ghsa:\n    - "${adv.ghsa_id}"\n`;
  const externalBlock =
    refExternal.length > 0
      ? `  external:\n${refExternal.map((u) => `    - "${u}"`).join("\n")}\n`
      : "";

  const severity = (adv.severity || "high").toLowerCase();
  const sevAllow = new Set(["critical", "high", "medium", "low"]);
  const finalSeverity = sevAllow.has(severity) ? severity : "high";

  return `# ATR rule proposal -- generated by scripts/sync-ghsa.ts
# Source: GitHub Security Advisory ${adv.ghsa_id}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${adv.summary.replace(/"/g, '\\"').slice(0, 120)}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  GitHub Security Advisory ${adv.ghsa_id}${cveId ? ` (${cveId})` : ""}.
  ${adv.summary.replace(/\n+/g, " ").trim()}
author: "ATR Community (GHSA sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${finalSeverity}

references:
${cveBlock}${cweBlock}${ghsaBlock}${externalBlock}

metadata_provenance:
  ghsa: ghsa-sync
${cveId ? "  cve: ghsa-sync\n" : ""}${cwes.length ? "  cwe: ghsa-sync\n" : ""}

tags:
  category: ${category}
  scan_target: runtime
  confidence: ${triage.ready ? "high" : "low"}

agent_source:
  type: llm_io
  framework:
    - any
  provider:
    - any

detection:
  condition: any
  false_positives: []
  conditions:
    # TODO(human): fill in regex / pattern conditions derived from the
    # advisory PoC or vendor patch diff. Empty until promoted to rules/.
    []

response:
  actions:
    - alert
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason}"

# === sync-ghsa.ts provenance ===
_ghsa_sync:
  ghsa_id: "${adv.ghsa_id}"
  cve_id: ${cveId ? `"${cveId}"` : "null"}
  affected_packages:
${pkgList.map((p) => `    - "${p}"`).join("\n")}
  severity: "${adv.severity}"
  published_at: "${adv.published_at}"
  withdrawn_at: ${adv.withdrawn_at ? `"${adv.withdrawn_at}"` : "null"}
  html_url: "${adv.html_url}"
  advisory_summary: |
${indentForLiteralBlock(adv.summary ?? "", "    ")}
  advisory_body: |
${indentForLiteralBlock(adv.description ?? "(no body provided by GHSA API)", "    ")}
`;
}

async function main(): Promise<void> {
  if (!existsSync(PROPOSALS_DIR)) mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();
  const summary = {
    run_date: new Date().toISOString(),
    ecosystems_scanned: [] as string[],
    packages_queried: 0,
    advisories_seen: 0,
    advisories_withdrawn: 0,
    advisories_already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    written_files: [] as string[],
  };

  const ecosystems = ECOSYSTEM_FILTER
    ? [ECOSYSTEM_FILTER]
    : Object.keys(AI_PACKAGES);
  const sinceDate = SINCE ? new Date(SINCE) : null;
  let writtenCount = 0;

  for (const ecosystem of ecosystems) {
    summary.ecosystems_scanned.push(ecosystem);
    const pkgs = AI_PACKAGES[ecosystem] ?? [];
    for (const pkg of pkgs) {
      if (writtenCount >= LIMIT) break;
      summary.packages_queried += 1;
      let advs: GhsaAdvisory[];
      try {
        advs = await ghsaFetch(ecosystem, pkg);
      } catch (e) {
        console.error(`fetch failed for ${ecosystem}/${pkg}: ${e}`);
        continue;
      }
      if (VERBOSE) console.error(`${ecosystem}/${pkg}: ${advs.length} adv`);
      for (const adv of advs) {
        summary.advisories_seen += 1;
        if (ADVISORY_FILTER && adv.ghsa_id !== ADVISORY_FILTER) continue;
        if (adv.withdrawn_at) {
          summary.advisories_withdrawn += 1;
          continue;
        }
        if (sinceDate && new Date(adv.published_at) < sinceDate) continue;

        const cveId = adv.cve_id ?? null;
        if (cveId && known.cves.has(cveId)) {
          summary.advisories_already_known += 1;
          continue;
        }
        if (known.ghsas.has(adv.ghsa_id)) {
          summary.advisories_already_known += 1;
          continue;
        }

        const outName = `${adv.ghsa_id}.proposal.yaml`;
        const outPath = join(PROPOSALS_DIR, outName);
        if (existsSync(outPath) && !FORCE) {
          summary.advisories_already_known += 1;
          continue;
        }

        const triage = isDetectionReady(adv);
        const yamlBody = renderProposal(adv);
        summary.new_proposals += 1;
        if (triage.ready) summary.new_detection_ready += 1;
        else summary.new_tracking_only += 1;

        if (WRITE) {
          writeFileSync(outPath, yamlBody, "utf-8");
          summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
        } else if (VERBOSE) {
          console.log(`would write ${outPath}`);
        }
        writtenCount += 1;
      }
    }
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::ghsa-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      advisories_seen: summary.advisories_seen,
      packages_queried: summary.packages_queried,
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
