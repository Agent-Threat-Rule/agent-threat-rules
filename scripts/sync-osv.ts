#!/usr/bin/env npx tsx
/**
 * sync-osv.ts
 *
 * Pulls OSV.dev (Google Open Source Vulnerabilities) advisories for AI /
 * agent / LLM / MCP ecosystem packages and emits ATR rule proposals under
 * proposals/osv/<CVE-or-OSV-id>.proposal.yaml.
 *
 * Why OSV in addition to GHSA:
 *   OSV aggregates many databases (GHSA, PySec, PyPA, OSV-Malicious /
 *   OpenSSF Malicious Packages, RustSec, Go vuln db, ...). It HEAVILY
 *   overlaps GHSA because it ingests GHSA. We therefore dedup by CVE id
 *   (pulled from each record's aliases[]) against everything already in
 *   rules/ and proposals/. The NET-NEW value of OSV is:
 *     (a) PyPA / PYSEC / OSV-native advisories not yet mirrored into GHSA,
 *     (b) OpenSSF Malicious Packages (MAL-* records) that GHSA does not carry,
 *     (c) ecosystems beyond pip/npm (crates.io, Go, RubyGems, Maven, NuGet).
 *   Anything whose CVE already exists in the repo is skipped.
 *
 * Data source (verified, no auth, no documented rate limit):
 *   Batch query: POST https://api.osv.dev/v1/querybatch
 *     body {"queries":[{"package":{"name":"langchain","ecosystem":"PyPI"}}, ...]}
 *     -> per-query {vulns:[{id, modified}]}  (IDs only)
 *   Detail:      GET https://api.osv.dev/v1/vulns/{id}
 *     -> full OSV record (id, summary, details, affected[], references[],
 *        aliases[] (contains CVE-xxxx), database_specific.cwe_ids/severity)
 *
 * Scope (same agent-runtime allowlist + second gate as sync-ghsa.ts):
 *   - AI_PACKAGES is the SAME curated agent allowlist as sync-ghsa.ts, mapped
 *     to OSV ecosystem names (pip->PyPI, npm->npm, maven->Maven, nuget->NuGet,
 *     go->Go, rubygems->RubyGems). The broad ML-infra packages
 *     (vllm/torch/ray/mlflow/gradio/tensorflow/...) are deliberately EXCLUDED.
 *   - agentRelevance() second gate (reused logic from sync-ghsa.ts): even
 *     inside the allowlist, only keep advisories whose CWE/summary indicates an
 *     agent-runtime threat (injection/RCE/SSRF/path-traversal/deser/info-
 *     exposure/access-control). Pure DoS / memory-safety crashes are dropped.
 *
 * Detection-readiness triage:
 *   The proposal is written with empty detection.conditions. The OSV record's
 *   `details` field (long markdown advisory body, often with PoC / code blocks)
 *   is stored in _osv_sync.advisory_body. _triage.detection_ready=true when
 *   details contains a fenced code block or payload-like content, else false.
 *
 * Usage:
 *   npx tsx scripts/sync-osv.ts                  # dry-run, all ecosystems
 *   npx tsx scripts/sync-osv.ts --write          # write proposals
 *   npx tsx scripts/sync-osv.ts --force          # overwrite existing
 *   npx tsx scripts/sync-osv.ts --limit 50       # cap output
 *   npx tsx scripts/sync-osv.ts --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path available (recoverable — e.g. OSV batch endpoint down)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "osv");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const USER_AGENT =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// ---------------------------------------------------------------------------
// AI AGENT package allowlist.
// SAME curated agent allowlist as sync-ghsa.ts (agent frameworks + agent
// infra/protocol + runtime guardrails + LLM IO SDKs), but keyed by OSV
// ecosystem names. The broad ML-infra packages (tensorflow, torch,
// onnxruntime, gradio, mlflow, ray, diffusers, datasets, accelerate,
// huggingface-hub, transformers, vllm) are deliberately EXCLUDED per ATR
// scope — they produced the bulk of prior noise. agentRelevance() is the
// second gate so even an injection CWE inside an out-of-scope package never
// slips through.
//
// Ecosystem-name mapping vs sync-ghsa.ts:
//   pip -> PyPI, npm -> npm, maven -> Maven, nuget -> NuGet,
//   go -> Go, rubygems -> RubyGems  (OSV's exact ecosystem strings).
// ---------------------------------------------------------------------------
const AI_PACKAGES: Record<string, string[]> = {
  PyPI: [
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
  Maven: [
    "dev.langchain4j:langchain4j",
    "com.theokanning.openai-gpt3-java:api",
  ],
  NuGet: ["Microsoft.SemanticKernel", "OpenAI"],
  Go: ["github.com/tmc/langchaingo", "github.com/sashabaranov/go-openai"],
  RubyGems: ["langchainrb", "ruby-openai", "anthropic"],
};

// CWE → ATR category (same mapping as sync-ghsa.ts).
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

// CWEs that map to an agent-runtime threat ATR can detect at the content
// layer (same set as sync-ghsa.ts). Deliberately excludes memory-safety /
// availability CWEs (the DoS / kernel-crash noise class).
const AGENT_RELEVANT_CWES = new Set([
  "CWE-94", // code injection
  "CWE-95", // eval injection
  "CWE-77", // command injection
  "CWE-78", // OS command injection
  "CWE-917", // expression language / template injection
  "CWE-1336", // server-side template injection (prompt)
  "CWE-918", // SSRF
  "CWE-22", // path traversal
  "CWE-23", // relative path traversal
  "CWE-611", // XXE
  "CWE-502", // deserialization of untrusted data
  "CWE-89", // SQL injection
  "CWE-79", // XSS
  "CWE-74", // injection (general)
  "CWE-470", // unsafe reflection
  "CWE-601", // open redirect
  "CWE-862", // missing authorization
  "CWE-863", // incorrect authorization
  "CWE-200", // sensitive info exposure
  "CWE-20", // improper input validation (maps to prompt-injection)
]);

// Agent-threat phrases (same set as sync-ghsa.ts) — second signal when the
// CWE list is absent/uninformative.
const AGENT_THREAT_KEYWORDS: RegExp[] = [
  /prompt injection/,
  /prompt-injection/,
  /system prompt/,
  /jailbreak/,
  /tool call/,
  /tool-calling/,
  /tool poisoning/,
  /model context protocol/,
  /\bmcp\b/,
  /\bssrf\b/,
  /server-side request/,
  /remote code execution/,
  /\brce\b/,
  /arbitrary code/,
  /code execution/,
  /command injection/,
  /deserializ/,
  /sql injection/,
  /path traversal/,
  /template injection/,
  /sandbox escape/,
  /exfiltrat/,
  /malicious (package|code|payload)/,
  /untrusted (input|data|manifest|model|content)/,
];

// Second gate (after the package allowlist), reusing sync-ghsa.ts logic: is
// this specific advisory an agent-runtime threat ATR could write a detection
// rule for? Relevant if it carries an agent-relevant CWE OR an agent-threat
// keyword. Pure DoS / kernel crashes (excluded CWEs, no injection wording)
// are dropped. OSV-Malicious (MAL-*) records are always relevant — a
// malicious package IS a supply-chain agent-runtime threat.
export function agentRelevance(adv: {
  id?: string;
  summary?: string;
  details?: string;
  cwes?: string[];
}): { relevant: boolean; reason: string } {
  if ((adv.id ?? "").startsWith("MAL-"))
    return { relevant: true, reason: "OpenSSF Malicious Package (MAL-*)" };
  const cwes = adv.cwes ?? [];
  const hitCwe = cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const body = `${adv.summary ?? ""}\n${adv.details ?? ""}`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  return {
    relevant: false,
    reason: `no agent-relevant CWE or keyword (cwes: ${cwes.join(",") || "none"})`,
  };
}

// ---------------------------------------------------------------------------
// OSV API types.
// ---------------------------------------------------------------------------
interface OsvBatchVulnRef {
  id: string;
  modified?: string;
}
interface OsvBatchResult {
  vulns?: OsvBatchVulnRef[];
}
interface OsvBatchResponse {
  results?: OsvBatchResult[];
}
interface OsvReference {
  type?: string;
  url: string;
}
interface OsvAffectedPackage {
  name?: string;
  ecosystem?: string;
  purl?: string;
}
interface OsvAffected {
  package?: OsvAffectedPackage;
  ranges?: unknown;
  versions?: string[];
}
interface OsvSeverity {
  type?: string;
  score?: string;
}
interface OsvRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  withdrawn?: string;
  affected?: OsvAffected[];
  references?: OsvReference[];
  severity?: OsvSeverity[];
  database_specific?: {
    cwe_ids?: string[];
    severity?: string;
    [k: string]: unknown;
  };
}

async function osvBatchQuery(
  ecosystem: string,
  packages: string[],
): Promise<Map<string, OsvBatchVulnRef[]>> {
  const body = {
    queries: packages.map((name) => ({ package: { name, ecosystem } })),
  };
  const resp = await fetch(OSV_BATCH_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
    },
    body: JSON.stringify(body),
  });
  if (resp.status === 429) {
    console.error(`OSV batch rate limited for ecosystem ${ecosystem}`);
    process.exit(2);
  }
  if (!resp.ok) {
    throw new Error(
      `OSV batch query failed for ${ecosystem}: ${resp.status} ${resp.statusText}`,
    );
  }
  const data = (await resp.json()) as OsvBatchResponse;
  const out = new Map<string, OsvBatchVulnRef[]>();
  const results = data.results ?? [];
  packages.forEach((name, i) => {
    out.set(name, results[i]?.vulns ?? []);
  });
  return out;
}

async function osvVulnDetail(id: string): Promise<OsvRecord | null> {
  const resp = await fetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
    headers: { "User-Agent": USER_AGENT },
  });
  if (resp.status === 429) {
    console.error(`OSV detail rate limited on ${id}`);
    process.exit(2);
  }
  if (!resp.ok) {
    if (VERBOSE)
      console.error(`detail fetch non-200 for ${id}: ${resp.status}`);
    return null;
  }
  return (await resp.json()) as OsvRecord;
}

// ---------------------------------------------------------------------------
// Field extractors.
// ---------------------------------------------------------------------------
function cveFromAliases(rec: OsvRecord): string | null {
  for (const a of rec.aliases ?? []) {
    if (typeof a === "string" && /^CVE-\d{4}-\d+$/i.test(a))
      return a.toUpperCase();
  }
  return null;
}

function cwesFromRecord(rec: OsvRecord): string[] {
  const raw = rec.database_specific?.cwe_ids ?? [];
  return raw
    .filter((c): c is string => typeof c === "string")
    .map((c) => c.trim())
    .filter(Boolean);
}

function severityFromRecord(
  rec: OsvRecord,
): "critical" | "high" | "medium" | "low" {
  const v = (rec.database_specific?.severity ?? "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "moderate" || v === "medium") return "medium";
  if (v === "low") return "low";
  // No GHSA-style severity label. Fall back from CVSS vector severity[].score
  // if present, else default to high (conservative for response.actions).
  const cvss = rec.severity?.find((s) => /cvss/i.test(s.type ?? ""));
  if (cvss?.score) {
    const m = cvss.score.match(/\/AV:|CVSS:[0-9.]+/i);
    if (m) return "high";
  }
  return "high";
}

function affectedPackages(rec: OsvRecord): string[] {
  const out: string[] = [];
  for (const a of rec.affected ?? []) {
    const p = a.package;
    if (p?.name) out.push(`${p.ecosystem ?? "?"}:${p.name}`);
  }
  return out.length ? out : ["unknown"];
}

function externalRefs(rec: OsvRecord): string[] {
  return (rec.references ?? [])
    .map((r) => r?.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
}

// detection_ready: details contains a fenced code block OR payload-like
// content. Mirrors sync-ghsa.ts PAYLOAD_HEURISTICS_RX.
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

function isDetectionReady(rec: OsvRecord): { ready: boolean; reason: string } {
  const details = rec.details ?? "";
  if (PAYLOAD_HEURISTICS_RX.test(details))
    return {
      ready: true,
      reason: "fenced code block / payload-like content in OSV details",
    };
  if (externalRefs(rec).some((r) => /poc|exploit-db|cve\.org/.test(r)))
    return { ready: true, reason: "PoC reference link present" };
  return {
    ready: false,
    reason: "OSV details has no fenced code block / reproducer / payload",
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE/OSV ids across rules/ and proposals/.
// (buildKnownIndex pattern from sync-huntr / sync-ghsa.)
// ---------------------------------------------------------------------------
function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

interface KnownIndex {
  cves: Set<string>;
  osvs: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const osvs = new Set<string>();
  for (const dir of [RULES_DIR, PROPOSALS_BASE]) {
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
      const refs = (
        doc as {
          references?: {
            cve?: string[];
            osv?: string[] | string;
            ghsa?: string[];
          };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
      // GHSA ids are also OSV ids — treat them as known OSV ids so an OSV
      // record whose id IS a GHSA already imported by sync-ghsa is skipped.
      if (refs?.ghsa)
        for (const g of refs.ghsa) if (typeof g === "string") osvs.add(g);
      if (refs?.osv) {
        const v = refs.osv;
        if (typeof v === "string") osvs.add(v);
        else if (Array.isArray(v))
          for (const o of v) if (typeof o === "string") osvs.add(o);
      }
    }
  }
  return { cves, osvs };
}

// ---------------------------------------------------------------------------
// Proposal renderer (逐欄 aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------
const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see OSV record for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(rec: OsvRecord): string {
  const cveId = cveFromAliases(rec);
  const cwes = cwesFromRecord(rec);
  const category = guessCategory(cwes);
  const severity = severityFromRecord(rec);
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = cveId ?? rec.id;
  const draftIdSuffix = cveId ? cveId.replace(/^CVE-/i, "") : rec.id;
  const triage = isDetectionReady(rec);

  const summary = (rec.summary || rec.id).replace(/\n+/g, " ").trim();
  const title = summary.replace(/"/g, '\\"').slice(0, 120);
  const pkgList = affectedPackages(rec);
  const refExternal = externalRefs(rec);

  const responseActions =
    severity === "critical" || severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = cveId ? `  cve:\n    - "${cveId}"\n` : "";
  const cweBlock =
    cwes.length > 0
      ? `  cwe:\n${cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const externalBlock =
    refExternal.length > 0
      ? `  external:\n${refExternal.map((u) => `    - "${u}"`).join("\n")}\n`
      : "";

  return `# ATR rule proposal -- generated by scripts/sync-osv.ts
# Source: OSV.dev record ${rec.id}${cveId ? ` (${cveId})` : ""}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The OSV advisory body
#         (details) is attached under _osv_sync.advisory_body as the payload
#         source for promote-detection-ready.ts.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  OSV.dev advisory ${rec.id}${cveId ? ` (${cveId})` : ""}.
  Affected: ${pkgList.join(", ")}.
  ${summary.slice(0, 600)}
author: "ATR Community (OSV sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${cweBlock}  osv:
    - "${rec.id}"
${externalBlock}
metadata_provenance:
  osv: osv-sync
${cveId ? "  cve: osv-sync\n" : ""}${cwes.length ? "  cwe: osv-sync\n" : ""}
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
    # TODO(human): convert the OSV advisory body (see _osv_sync.advisory_body
    # below) into precision-safe detection.conditions regex/string matchers.
    # Empty until promoted to rules/. Without this the rule will neither fire
    # nor be promotable.
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"

# === sync-osv.ts provenance ===
_osv_sync:
  osv_id: "${rec.id}"
  cve_id: ${cveId ? `"${cveId}"` : "null"}
  aliases: ${JSON.stringify(rec.aliases ?? [])}
  affected_packages:
${pkgList.map((p) => `    - "${p}"`).join("\n")}
  severity: "${rec.database_specific?.severity ?? severity}"
  published: ${rec.published ? `"${rec.published}"` : "null"}
  modified: ${rec.modified ? `"${rec.modified}"` : "null"}
  withdrawn: ${rec.withdrawn ? `"${rec.withdrawn}"` : "null"}
  cwe_ids: ${JSON.stringify(cwes)}
  imported_at: "${new Date().toISOString()}"
  data_source_used: "OSV.dev /v1/querybatch + /v1/vulns"
  advisory_summary: |
${indentForLiteralBlock(rec.summary ?? "", "    ")}
  advisory_body: |
${indentForLiteralBlock(rec.details ?? "(no details provided by OSV)", "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------
interface RunSummary {
  run_date: string;
  ecosystems_scanned: string[];
  packages_queried: number;
  osv_ids_seen: number;
  records_fetched: number;
  withdrawn: number;
  filtered_not_agent: number;
  already_known_cve: number;
  already_known_osv: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  errors: string[];
  written_files: string[];
}

async function main(): Promise<void> {
  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    ecosystems_scanned: [],
    packages_queried: 0,
    osv_ids_seen: 0,
    records_fetched: 0,
    withdrawn: 0,
    filtered_not_agent: 0,
    already_known_cve: 0,
    already_known_osv: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-osv.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  // Step 1: batch-query OSV for every allowlisted package per ecosystem,
  // collect the union of vuln ids.
  const idToEcosystems = new Map<string, Set<string>>();
  for (const ecosystem of Object.keys(AI_PACKAGES)) {
    const packages = AI_PACKAGES[ecosystem];
    summary.ecosystems_scanned.push(ecosystem);
    summary.packages_queried += packages.length;
    let batch: Map<string, OsvBatchVulnRef[]>;
    try {
      batch = await osvBatchQuery(ecosystem, packages);
    } catch (e) {
      summary.errors.push(`batch ${ecosystem}: ${(e as Error).message}`);
      if (VERBOSE) console.error(`  batch failed ${ecosystem}: ${e}`);
      continue;
    }
    for (const [pkg, vulns] of batch) {
      if (VERBOSE && vulns.length)
        console.error(`  ${ecosystem}/${pkg}: ${vulns.length} osv ids`);
      for (const v of vulns) {
        if (!idToEcosystems.has(v.id)) idToEcosystems.set(v.id, new Set());
        idToEcosystems.get(v.id)!.add(ecosystem);
      }
    }
  }

  summary.osv_ids_seen = idToEcosystems.size;
  console.error(`OSV ids collected (deduped): ${summary.osv_ids_seen}`);

  // No data path at all -> recoverable exit 2.
  if (summary.osv_ids_seen === 0) {
    summary.errors.push(
      "OSV returned no vuln ids for any allowlisted package — likely a " +
        "transient OSV outage or batch schema change. Retry later.",
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::osv-summary::${JSON.stringify({
        new_proposals: 0,
        osv_ids_seen: 0,
        records_fetched: 0,
        new_detection_ready: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  // Step 2: fetch detail for each id, gate, dedup, render.
  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const [id] of idToEcosystems) {
    if (writtenCount >= LIMIT) break;

    // Dedup against repo BEFORE fetching detail when the OSV id itself is
    // already known (e.g. a GHSA-* id imported by sync-ghsa).
    if (!FORCE && known.osvs.has(id)) {
      summary.already_known_osv += 1;
      if (VERBOSE) console.error(`  skip ${id}: osv/ghsa id already in repo`);
      continue;
    }

    let rec: OsvRecord | null;
    try {
      rec = await osvVulnDetail(id);
    } catch (e) {
      summary.errors.push(`detail ${id}: ${(e as Error).message}`);
      continue;
    }
    if (!rec) continue;
    summary.records_fetched += 1;

    if (rec.withdrawn) {
      summary.withdrawn += 1;
      if (VERBOSE) console.error(`  skip ${id}: withdrawn`);
      continue;
    }

    const cveId = cveFromAliases(rec);
    const cwes = cwesFromRecord(rec);

    // CVE-id dedup — primary cross-source key. The NET-NEW value of OSV is
    // records whose CVE is NOT already covered (PyPA/PYSEC-only, MAL-*,
    // non-pip/npm ecosystems). Skip anything already covered by GHSA etc.
    if (!FORCE && cveId && known.cves.has(cveId)) {
      summary.already_known_cve += 1;
      if (VERBOSE)
        console.error(`  skip ${id}: CVE ${cveId} already covered (GHSA overlap)`);
      continue;
    }

    // Agent-relevance second gate (same as sync-ghsa).
    const relevance = agentRelevance({
      id: rec.id,
      summary: rec.summary,
      details: rec.details,
      cwes,
    });
    if (!relevance.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE) console.error(`  skip (not agent) ${id}: ${relevance.reason}`);
      continue;
    }

    const outName = `${cveId ?? rec.id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known_osv += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const triage = isDetectionReady(rec);
    const body = renderProposal(rec);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(
        `  would write ${outName} [${triage.ready ? "READY" : "tracking"}]`,
      );
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::osv-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      filtered_not_agent: summary.filtered_not_agent,
      already_known_cve: summary.already_known_cve,
      already_known_osv: summary.already_known_osv,
      osv_ids_seen: summary.osv_ids_seen,
      records_fetched: summary.records_fetched,
      data_source_used: "OSV.dev",
    })}`,
  );
}

// Run if invoked as a script (not when imported as a module for tests).
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
