#!/usr/bin/env npx tsx
/**
 * sync-nuclei.ts
 *
 * Pulls projectdiscovery/nuclei-templates community exploit templates and
 * emits ATR rule proposals under proposals/nuclei/<CVE-or-templateid>.proposal.yaml.
 *
 * Why nuclei: each template's `matchers` (words / regex / dsl) plus its
 * `http`/`requests` payload are effectively a pre-written detection signature
 * for a known CVE. For an in-scope agent-runtime CVE this is gold: the
 * reviewer gets both the attack request (poc_body) and the detection matcher
 * already extracted, so the proposal is detection-ready out of the box.
 *
 * Data source strategy:
 *   PRIMARY  Machine index:
 *     https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json
 *     This is NDJSON (one JSON object per line, ~4000 entries), NOT a single
 *     JSON array. Each line:
 *       { "ID": "CVE-2025-49596",
 *         "Info": { "Name": ..., "Severity": ..., "Description": ...,
 *                   "Classification": { "CVSSScore": "9.8", ... } },
 *         "file_path": "http/cves/2025/CVE-2025-49596.yaml" }
 *     NOTE: cves.json's Classification only carries CVSSScore — the cve-id and
 *     cwe-id live inside the per-template YAML's info.classification, so we
 *     fetch the template YAML for every in-scope entry.
 *
 *   Per-template YAML (fetched raw from file_path): has info.classification
 *     (cve-id, cwe-id), info.tags (CSV), info.reference[], and http/requests
 *     carrying the payload + matchers (words/regex/dsl).
 *
 * CRITICAL SCOPE FILTER (the whole point of this script):
 *   nuclei's "AI" coverage is DOMINATED by ML-infra web exploits — Gradio /
 *   MLflow / Ray / H2O / AnythingLLM / BentoML / ComfyUI LFI/SSRF/path-traversal.
 *   ATR DELIBERATELY EXCLUDES ML infra (same scope rule as sync-ghsa.ts). So we
 *   keep ONLY agent-runtime-relevant templates: agent frameworks
 *   (langchain/llama-index/crewai/autogen/flowise/astrbot/chuanhu), MCP
 *   servers/clients/inspectors, and LLM gateways (litellm/ollama) — matched via
 *   the sync-ghsa AI_PACKAGES allowlist (extended with the agent *products*
 *   nuclei ships templates for) against the template's product / path / name /
 *   tags / references. Everything mlflow/gradio/ray/h2o/anythingllm/comfyui/
 *   bentoml is dropped and counted as out_of_scope_dropped.
 *
 * Dedup: by CVE id (top-level ID / classification.cve-id) against rules/ +
 *   proposals/ (buildKnownIndex, reusing sync-huntr's index over references.cve).
 *   Many nuclei CVEs already exist via GHSA / vulnerablemcp — those are skipped.
 *
 * Usage:
 *   npx tsx scripts/sync-nuclei.ts                 # dry-run
 *   npx tsx scripts/sync-nuclei.ts --write         # write proposals
 *   npx tsx scripts/sync-nuclei.ts --force         # overwrite existing
 *   npx tsx scripts/sync-nuclei.ts --verbose
 *   npx tsx scripts/sync-nuclei.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path available (recoverable — index unreachable)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "nuclei");

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

const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

const NT_OWNER = "projectdiscovery";
const NT_REPO = "nuclei-templates";
const NT_REF = "main";
const CVES_INDEX_URL = `https://raw.githubusercontent.com/${NT_OWNER}/${NT_REPO}/${NT_REF}/cves.json`;

// Be polite to raw.githubusercontent.com between per-template fetches.
const RATE_LIMIT_MS = 250;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// SCOPE: agent-runtime allowlist.
//
// Base = the sync-ghsa.ts AI_PACKAGES allowlist (agent frameworks + agent
// infra/protocol + LLM-gateway/IO SDKs). Extended with the agent *products*
// nuclei actually ships exploit templates for (Flowise, MCP Inspector / MCPJam,
// AstrBot, Chuanhu Chat) which are agent runtimes but not pip/npm package names.
//
// Intentionally EXCLUDED (ML infra — the bulk of nuclei's "AI" templates, zero
// agent-runtime relevance, same exclusion as sync-ghsa.ts):
//   mlflow, gradio, ray, h2o, anythingllm, bentoml, comfyui, triton,
//   tensorflow, torch, onnxruntime, diffusers, vllm
// These are matched explicitly and dropped (counted out_of_scope_dropped) so
// the summary is honest about how many ML-infra templates were skipped.
// ---------------------------------------------------------------------------

// Tokens that mark a template as AGENT-RUNTIME in scope. Matched (word-ish,
// bounded) against product/path/name/tags/reference text.
const AGENT_SCOPE_TOKENS: string[] = [
  // agent frameworks
  "langchain",
  "langgraph",
  "langsmith",
  "llama-index",
  "llamaindex",
  "llama_index",
  "crewai",
  "crew-ai",
  "autogen",
  "pyautogen",
  "semantic-kernel",
  "semantic kernel",
  "pydantic-ai",
  "haystack",
  "dspy",
  "embedchain",
  "flowise",
  "astrbot",
  "chuanhu",
  "chatgpt-next-web",
  "lobe-chat",
  "lobechat",
  "dify",
  "open-webui",
  "openwebui",
  "anything-llm-agent", // NOTE: bare "anythingllm" is OUT of scope (see below)
  // MCP protocol / servers / clients
  "mcp",
  "model context protocol",
  "modelcontextprotocol",
  "fastmcp",
  "mcpjam",
  // LLM gateways / runtimes / IO SDKs
  "litellm",
  "ollama",
  "openrouter",
  "vllm-gateway",
];

// Hard exclusions — ML infra. If a template hits one of these and is NOT
// rescued by a strong agent token, it is dropped as out-of-scope. Matched
// against product/path/name/tags.
const ML_INFRA_EXCLUSIONS: string[] = [
  "mlflow",
  "gradio",
  "anyscale",
  "ray", // "Anyscale Ray" / "Ray API" — boundaried, won't match "liferay"
  "h2o",
  "anythingllm",
  "anything-llm",
  "bentoml",
  "comfyui",
  "comfy-ui",
  "triton",
  "tensorflow",
  "onnxruntime",
  "diffusers",
  "kubeflow",
  "kserve",
  "sagemaker",
];

// Word-ish boundary test so "mcp" doesn't match "mcphersonville" etc.
function tokenHit(haystack: string, token: string): boolean {
  if (token.includes(" ")) return haystack.includes(token);
  // boundary on non-alphanumeric (treat - and _ and / as separators by also
  // allowing them as boundaries via the broader char class)
  const esc = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rx = new RegExp(`(?:^|[^a-z0-9])${esc}(?:[^a-z0-9]|$)`, "i");
  return rx.test(haystack);
}

interface ScopeVerdict {
  inScope: boolean;
  reason: string;
  matchedToken: string | null;
  excludedBy: string | null;
}

// haystack = product + path + name + tags + references, all lowercased.
function classifyScope(haystack: string): ScopeVerdict {
  const lc = haystack.toLowerCase();
  const agentTok = AGENT_SCOPE_TOKENS.find((t) => tokenHit(lc, t));
  const mlTok = ML_INFRA_EXCLUSIONS.find((t) => tokenHit(lc, t));

  // Strong agent signal wins even if an ML term is also present (e.g. an MCP
  // server that wraps an ML tool). But the bare ML-infra products below should
  // never be rescued by an incidental "ai"/"llm" tag, so we only rescue on a
  // real agent token.
  if (agentTok) {
    return {
      inScope: true,
      reason: `agent-scope token "${agentTok}"`,
      matchedToken: agentTok,
      excludedBy: null,
    };
  }
  if (mlTok) {
    return {
      inScope: false,
      reason: `ML-infra exclusion "${mlTok.trim()}" (out of ATR scope)`,
      matchedToken: null,
      excludedBy: mlTok.trim(),
    };
  }
  return {
    inScope: false,
    reason: "no agent-scope token (not an agent runtime / MCP / LLM gateway)",
    matchedToken: null,
    excludedBy: null,
  };
}

// ---------------------------------------------------------------------------
// CWE → ATR category (reuse sync-ghsa.ts mapping; fallback model-abuse).
// ---------------------------------------------------------------------------
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
  "CWE-306": "privilege-escalation", // missing authentication
  "CWE-287": "privilege-escalation",
  "CWE-284": "privilege-escalation",
  "CWE-74": "tool-poisoning",
  "CWE-95": "model-abuse",
};

function guessCategory(cwes: string[]): string {
  for (const c of cwes) if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// cves.json (NDJSON) index parsing.
// ---------------------------------------------------------------------------

interface CveIndexEntry {
  ID: string;
  Info?: {
    Name?: string;
    Severity?: string;
    Description?: string;
    Classification?: {
      CVSSScore?: string | number;
      CVEID?: string;
      CWEID?: string;
    };
  };
  file_path?: string;
}

async function fetchCvesIndex(): Promise<CveIndexEntry[]> {
  const res = await fetch(CVES_INDEX_URL, {
    headers: { "User-Agent": POLITE_UA },
  });
  if (!res.ok)
    throw new Error(
      `cves.json fetch failed: ${res.status} ${res.statusText}`,
    );
  const text = await res.text();
  const out: CveIndexEntry[] = [];
  // NDJSON: one object per line. Tolerate a trailing/leading [ ] in case the
  // upstream format ever switches to a real array.
  const trimmed = text.trim();
  if (trimmed.startsWith("[")) {
    const arr = JSON.parse(trimmed) as CveIndexEntry[];
    return Array.isArray(arr) ? arr : [];
  }
  for (const line of trimmed.split("\n")) {
    const l = line.trim().replace(/,$/, "");
    if (!l || l === "[" || l === "]") continue;
    try {
      out.push(JSON.parse(l) as CveIndexEntry);
    } catch {
      // skip malformed line; keep going
    }
  }
  return out;
}

async function fetchTemplate(path: string): Promise<string> {
  const u = `https://raw.githubusercontent.com/${NT_OWNER}/${NT_REPO}/${NT_REF}/${path}`;
  const res = await fetch(u, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok)
    throw new Error(
      `template fetch failed for ${path}: ${res.status} ${res.statusText}`,
    );
  return await res.text();
}

// ---------------------------------------------------------------------------
// Nuclei template parsing (reuses sync-huntr's NucleiTemplate shape +
// pocFromTemplate approach).
// ---------------------------------------------------------------------------

interface NucleiTemplate {
  id?: string;
  info?: {
    name?: string;
    author?: string;
    severity?: string;
    description?: string;
    reference?: string[];
    classification?: {
      "cvss-metrics"?: string;
      "cvss-score"?: number;
      "cve-id"?: string;
      "cwe-id"?: string | string[];
    };
    tags?: string;
  };
  requests?: unknown;
  http?: unknown;
}

function parseSeverity(
  s: string | undefined,
): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "medium";
}

// Reuse sync-huntr's pocFromTemplate: dump the requests/http block (payload +
// matchers) as the PoC body for the proposal.
function pocFromTemplate(t: NucleiTemplate): string | null {
  const r = (t.requests ?? t.http) as unknown;
  if (!r) return null;
  try {
    return yaml.dump(r, { lineWidth: 100 });
  } catch {
    return null;
  }
}

function cwesFromClassification(
  c: NucleiTemplate["info"] extends infer X
    ? X extends { classification?: infer C }
      ? C
      : never
    : never,
): string[] {
  if (!c) return [];
  const v = (c as { "cwe-id"?: string | string[] })["cwe-id"];
  if (!v) return [];
  if (Array.isArray(v))
    return v
      .map((s) => (typeof s === "string" ? s.split("#")[0].trim() : ""))
      .map((s) => s.toUpperCase())
      .filter((s): s is string => !!s);
  return [v.toString().split("#")[0].trim().toUpperCase()];
}

// Extract the matchers (the detection signature) from every http/requests
// stanza, as a compact YAML snippet to embed in the advisory body so the rule
// author has the words/regex/dsl ready to convert.
function matchersFromTemplate(t: NucleiTemplate): string | null {
  const blocks = (t.requests ?? t.http) as unknown;
  if (!Array.isArray(blocks)) return null;
  const matchers: unknown[] = [];
  for (const b of blocks) {
    const m = (b as { matchers?: unknown })?.matchers;
    if (Array.isArray(m)) matchers.push(...m);
  }
  if (matchers.length === 0) return null;
  try {
    return yaml.dump(matchers, { lineWidth: 100 });
  } catch {
    return null;
  }
}

interface NucleiAdvisory {
  cve_id: string | null;
  template_id: string; // top-level id or derived stable id
  template_path: string;
  template_url: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string[];
  cvss_score: number | string | null;
  cvss_metrics: string | null;
  tags: string[];
  references: string[];
  product_guess: string;
  poc_body: string | null; // payload (http/requests) as YAML
  matchers_body: string | null; // detection signature
  scope_reason: string;
}

function productFromPath(path: string): string {
  // http/cves/2025/CVE-2025-49596.yaml -> "CVE-2025-49596"; for non-cve paths
  // the leaf or the directory carries the product hint.
  const parts = path.split("/");
  return parts[parts.length - 1].replace(/\.ya?ml$/, "");
}

function templateToAdvisory(
  entry: CveIndexEntry,
  path: string,
  raw: string,
  scopeReason: string,
): NucleiAdvisory | { error: string } {
  let doc: NucleiTemplate;
  try {
    doc = yaml.load(raw) as NucleiTemplate;
    if (typeof doc !== "object" || doc === null)
      throw new Error("non-object yaml");
  } catch (e) {
    return { error: `yaml parse failed for ${path}: ${(e as Error).message}` };
  }
  const info = doc.info ?? {};
  const classCve = (info.classification?.["cve-id"] || "").toString().trim();
  // CVE id priority: classification.cve-id > top-level entry.ID (if CVE-shaped)
  // > derived. cves.json's entry.ID is the canonical id for cve templates.
  const idLooksCve = /^CVE-\d{4}-\d+$/i.test(entry.ID);
  const cveId =
    classCve || (idLooksCve ? entry.ID : null) || null;
  const cwes = cwesFromClassification(info.classification);
  const tags = (info.tags || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const references = Array.isArray(info.reference)
    ? info.reference.filter((r): r is string => typeof r === "string")
    : [];
  const templateId = (doc.id || entry.ID || productFromPath(path)).toString();
  return {
    cve_id: cveId ? cveId.toUpperCase() : null,
    template_id: templateId,
    template_path: path,
    template_url: `https://github.com/${NT_OWNER}/${NT_REPO}/blob/${NT_REF}/${path}`,
    title: (info.name || entry.Info?.Name || templateId).trim(),
    description: (info.description || entry.Info?.Description || "").trim(),
    severity: parseSeverity(info.severity || entry.Info?.Severity),
    cwe: cwes,
    cvss_score:
      info.classification?.["cvss-score"] ??
      entry.Info?.Classification?.CVSSScore ??
      null,
    cvss_metrics: info.classification?.["cvss-metrics"] || null,
    tags,
    references,
    product_guess: productFromPath(path),
    poc_body: pocFromTemplate(doc),
    matchers_body: matchersFromTemplate(doc),
    scope_reason: scopeReason,
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE ids across rules/ and proposals/.
// (Same approach as sync-huntr.buildKnownIndex — references.cve is the
// cross-source primary key. Also picks up CVE ids from filenames.)
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
  templateIds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const templateIds = new Set<string>();
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
          references?: { cve?: string[]; nuclei_id?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") {
            const m = c.match(/CVE-\d{4}-\d+/i);
            if (m) cves.add(m[0].toUpperCase());
          }
      if (refs?.nuclei_id) {
        const v = refs.nuclei_id;
        if (typeof v === "string") templateIds.add(v);
        else if (Array.isArray(v))
          for (const t of v) if (typeof t === "string") templateIds.add(t);
      }
      // Pick up CVE ids embedded in the filename too.
      const fm = f.match(/CVE-\d{4}-\d+/i);
      if (fm) cves.add(fm[0].toUpperCase());
    }
  }
  return { cves, templateIds };
}

// ---------------------------------------------------------------------------
// detection-ready triage.
// nuclei templates ALWAYS carry a payload (http/requests) + matchers, so an
// advisory with a parsed poc_body OR matchers_body is detection-ready.
// ---------------------------------------------------------------------------
function isDetectionReady(a: NucleiAdvisory): {
  ready: boolean;
  reason: string;
} {
  if (a.poc_body && a.matchers_body)
    return {
      ready: true,
      reason: "nuclei template carries exploit payload + detection matchers",
    };
  if (a.poc_body)
    return { ready: true, reason: "nuclei template carries exploit payload" };
  if (a.matchers_body)
    return { ready: true, reason: "nuclei template carries detection matchers" };
  return { ready: false, reason: "no payload/matchers parsed from template" };
}

// ---------------------------------------------------------------------------
// Proposal renderer (column-aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------

const BODY_MAX_CHARS = 8000;
function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > BODY_MAX_CHARS
      ? text.slice(0, BODY_MAX_CHARS) +
        `\n\n... (truncated at ${BODY_MAX_CHARS} chars; see template_url for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(a: NucleiAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = a.cve_id ?? `NUCLEI-${a.template_id}`;
  const draftIdSuffix = a.cve_id
    ? a.cve_id.replace(/^CVE-/i, "")
    : `NUCLEI-${a.template_id}`;
  const category = guessCategory(a.cwe);
  const triage = isDetectionReady(a);
  const responseActions =
    a.severity === "critical" || a.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = a.cve_id ? `  cve:\n    - "${a.cve_id}"\n` : "";
  const cweBlock =
    a.cwe.length > 0
      ? `  cwe:\n${a.cwe.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const nucleiBlock = `  nuclei_id:\n    - "${a.template_id}"\n`;
  const refExternal = [a.template_url, ...a.references].filter(
    (r, i, arr) => typeof r === "string" && r.length > 0 && arr.indexOf(r) === i,
  );
  const externalBlock =
    refExternal.length > 0
      ? `  external:\n${refExternal.map((u) => `    - "${u}"`).join("\n")}\n`
      : "";

  // PoC (payload) embedded as YAML comment under detection.conditions so a
  // human can convert it to precision-safe matchers (sync-huntr pattern).
  const pocCommentLines =
    a.poc_body
      ?.split("\n")
      .filter((s) => s.length > 0)
      .slice(0, 80)
      .map((s) => `    # ${s}`)
      .join("\n") ?? "";

  // test_cases.true_positives from the payload block.
  const tpBlock = a.poc_body
    ? `  true_positives:\n    - name: "nuclei template payload excerpt"\n      input: |\n${a.poc_body
        .split("\n")
        .slice(0, 40)
        .map((s) => `        ${s}`)
        .join("\n")}\n`
    : `  true_positives: []\n`;

  const title = a.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = (a.description || a.title).replace(/\n+/g, " ").trim();

  return `# ATR rule proposal -- generated by scripts/sync-nuclei.ts
# Source: projectdiscovery/nuclei-templates community exploit template
#         ${a.template_path}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The nuclei template's
#         exploit payload is attached as a YAML comment under
#         detection.conditions, and its matchers (words/regex/dsl) are in
#         _nuclei_sync.matchers_body, ready to convert into ATR conditions.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
# Scope: ${a.scope_reason}
title: "${title}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  nuclei-templates exploit template${a.cve_id ? ` (${a.cve_id})` : ""}.
  Product: ${a.product_guess}.
  ${desc.slice(0, 600)}
author: "ATR Community (Nuclei sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${a.severity}

references:
${cveBlock}${cweBlock}${nucleiBlock}${externalBlock}
metadata_provenance:
  nuclei_id: nuclei-sync
${a.cve_id ? "  cve: nuclei-sync\n" : ""}${a.cwe.length ? "  cwe: nuclei-sync\n" : ""}
tags:
  category: ${category}
  subcategory: nuclei-imported
  scan_target: runtime
  confidence: ${triage.ready ? "high" : "low"}

agent_source:
  type: tool_invocation
  framework:
    - any
  provider:
    - any

detection:
  condition: any
  false_positives: []
  conditions:
    # TODO(human): convert the nuclei exploit payload below + the matchers in
    # _nuclei_sync.matchers_body into precision-safe ATR detection.conditions.
    # Without this work the rule will neither fire nor be promotable to rules/.
    #
    # === Exploit payload (nuclei http/requests block) ===
${pocCommentLines || "    # (no payload parsed from template)"}
    []

response:
  actions:
${responseActions.map((x) => `    - ${x}`).join("\n")}
  notify:
    - security_team

confidence: 70

test_cases:
${tpBlock}  true_negatives:
    # TODO(human): add benign inputs that look similar to the payload but are
    # legitimate -- required before promoting out of draft.
    []

# === sync-nuclei.ts provenance ===
_nuclei_sync:
  discovered_by: "projectdiscovery/nuclei-templates via sync-nuclei.ts"
  template_id: "${a.template_id}"
  template_path: "${a.template_path}"
  template_url: "${a.template_url}"
  cve: ${a.cve_id ? `"${a.cve_id}"` : "null"}
  cwe: ${JSON.stringify(a.cwe)}
  product: "${a.product_guess}"
  cvss_score: ${a.cvss_score != null ? JSON.stringify(String(a.cvss_score)) : "null"}
  cvss_metrics: ${a.cvss_metrics ? `"${a.cvss_metrics.replace(/"/g, '\\"')}"` : "null"}
  tags: ${JSON.stringify(a.tags)}
  scope_reason: "${a.scope_reason.replace(/"/g, '\\"')}"
  imported_at: "${new Date().toISOString()}"
  data_source_used: "projectdiscovery/nuclei-templates cves.json"
  poc_body: |
${indentForLiteralBlock(a.poc_body ?? "(no payload in template)", "    ")}
  matchers_body: |
${indentForLiteralBlock(a.matchers_body ?? "(no matchers in template)", "    ")}

# Triage flag read by promote-detection-ready.ts. nuclei templates embed the
# exploit request itself plus the matchers, so a template with a parsed payload
# or matchers is detection-ready; the generator lifts patterns from poc_body /
# matchers_body, never from advisory prose.
_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  index_entries: number;
  in_scope_after_filter: number;
  out_of_scope_dropped: number;
  templates_fetched: number;
  parse_failures: number;
  already_known: number;
  no_cve_id_skipped: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  data_source_used: string | null;
  written_files: string[];
  errors: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    index_entries: 0,
    in_scope_after_filter: 0,
    out_of_scope_dropped: 0,
    templates_fetched: 0,
    parse_failures: 0,
    already_known: 0,
    no_cve_id_skipped: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    data_source_used: null,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-nuclei.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // --- fetch the cves.json machine index ---
  let index: CveIndexEntry[];
  try {
    index = await fetchCvesIndex();
  } catch (e) {
    summary.errors.push(`index fetch: ${(e as Error).message}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::nuclei-summary::${JSON.stringify({
        new_proposals: 0,
        index_entries: 0,
        in_scope_after_filter: 0,
        out_of_scope_dropped: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }
  summary.index_entries = index.length;
  summary.data_source_used = "projectdiscovery/nuclei-templates cves.json";
  console.error(`index: ${index.length} cve template entries`);

  // --- scope filter (index-level, cheap) ---
  // Build a haystack from the index fields available WITHOUT fetching each
  // template: name + description + file_path. The product token lives there.
  const inScope: Array<{ entry: CveIndexEntry; reason: string }> = [];
  for (const entry of index) {
    const haystack = [
      entry.ID,
      entry.Info?.Name ?? "",
      entry.Info?.Description ?? "",
      entry.file_path ?? "",
    ].join(" ");
    const verdict = classifyScope(haystack);
    if (verdict.inScope) {
      inScope.push({ entry, reason: verdict.reason });
    } else if (verdict.excludedBy) {
      // Only count explicit ML-infra hits as "dropped out-of-scope" — the vast
      // majority of nuclei templates are simply unrelated (not AI at all) and
      // are not interesting to report as drops.
      summary.out_of_scope_dropped += 1;
      if (VERBOSE)
        console.error(
          `  drop ML-infra ${entry.ID}: ${verdict.reason} (${entry.Info?.Name?.slice(0, 50)})`,
        );
    }
  }
  summary.in_scope_after_filter = inScope.length;
  console.error(
    `scope filter: ${inScope.length} agent-runtime in-scope / ` +
      `${summary.out_of_scope_dropped} ML-infra dropped / ` +
      `${index.length - inScope.length - summary.out_of_scope_dropped} unrelated`,
  );
  if (VERBOSE) {
    for (const { entry, reason } of inScope)
      console.error(`  in-scope ${entry.ID}: ${reason} (${entry.Info?.Name?.slice(0, 50)})`);
  }

  // --- dedup index + per-template fetch + render ---
  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const { entry, reason } of inScope) {
    if (writtenCount >= LIMIT) break;
    const path = entry.file_path;
    if (!path) {
      summary.errors.push(`no file_path for ${entry.ID}`);
      continue;
    }
    // Early CVE-level dedup using the index ID (avoids a network fetch).
    const idCve = /^CVE-\d{4}-\d+$/i.test(entry.ID)
      ? entry.ID.toUpperCase()
      : null;
    if (idCve && !FORCE && known.cves.has(idCve)) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-rule ${idCve}: already covered`);
      continue;
    }

    let raw: string;
    try {
      raw = await fetchTemplate(path);
      summary.templates_fetched += 1;
    } catch (e) {
      summary.parse_failures += 1;
      summary.errors.push(`fetch ${path}: ${(e as Error).message}`);
      continue;
    }
    await sleep(RATE_LIMIT_MS);

    const parsed = templateToAdvisory(entry, path, raw, reason);
    if ("error" in parsed) {
      summary.parse_failures += 1;
      if (VERBOSE) console.error(`  parse-skip ${path}: ${parsed.error}`);
      continue;
    }

    // CVE is the cross-source primary key. Require one (consistent with the
    // cves.json source being a CVE index).
    if (!parsed.cve_id) {
      summary.no_cve_id_skipped += 1;
      if (VERBOSE)
        console.error(`  skip ${parsed.template_id}: no CVE id resolvable`);
      continue;
    }

    // Re-dedup with the resolved CVE (template classification may carry a CVE
    // the index ID didn't).
    if (!FORCE && known.cves.has(parsed.cve_id)) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-rule ${parsed.cve_id}: already covered`);
      continue;
    }
    if (!FORCE && known.templateIds.has(parsed.template_id)) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-template ${parsed.template_id}: already covered`);
      continue;
    }

    const outName = `${parsed.cve_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const triage = isDetectionReady(parsed);
    const body = renderProposal(parsed);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(`  would write ${outName} (${triage.ready ? "READY" : "TRACKING"})`);
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::nuclei-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      index_entries: summary.index_entries,
      in_scope_after_filter: summary.in_scope_after_filter,
      out_of_scope_dropped: summary.out_of_scope_dropped,
      already_known: summary.already_known,
      templates_fetched: summary.templates_fetched,
      data_source_used: summary.data_source_used,
    })}`,
  );
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
