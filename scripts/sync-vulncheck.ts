#!/usr/bin/env npx tsx
/**
 * sync-vulncheck.ts
 *
 * Pulls AI / agent / LLM / MCP-relevant CVEs from VulnCheck (community tier)
 * and emits ATR rule proposals under
 * proposals/vulncheck/<CVE-id>.proposal.yaml.
 *
 * WHY VULNCHECK
 *   Two distinct values over the GHSA / OSV / CISA-KEV sources we already
 *   sync:
 *     1. VulnCheck KEV ("known exploited vulnerabilities") is a SUPERSET of
 *        CISA KEV -- ~142% broader -- so it carries an "exploited in the wild"
 *        signal for CVEs CISA has not yet (or will never) list. That signal is
 *        recorded on every proposal so a reviewer can prioritise.
 *     2. NVD++ (nist-nvd2) is a low-friction mirror of NVD 2.0 without NVD's
 *        rate-limit pain, used as a description backfill for KEV entries (KEV
 *        rows are metadata-thin) and as a discovery feed in its own right.
 *
 * SCOPE DISCIPLINE (critical -- this source is GENERAL-CVE, not AI-scoped)
 *   VulnCheck indexes the entire CVE universe. We MUST be strict or we drown
 *   ATR in irrelevant CVEs. Two gates, BOTH must pass, identical to the
 *   sync-ghsa.ts contract:
 *     Gate 1 (allowlist): the CVE's affected product / CPE / vendor text must
 *            match a known agent package name (AI_PACKAGES + AGENT_PACKAGE_RX).
 *     Gate 2 (agentRelevance): the CVE must carry an agent-relevant CWE OR an
 *            agent-threat keyword in its description.
 *   ML-infra packages (tensorflow, torch, onnxruntime, gradio, mlflow, ray,
 *   diffusers, datasets, accelerate, huggingface-hub, transformers, vllm) are
 *   deliberately NOT in the allowlist -- they produced ~251 noise rules before.
 *
 * DEDUP
 *   CVE id is the cross-source primary key. buildKnownIndex() scans rules/ and
 *   proposals/ for references.cve. Most KEV/NVD entries overlap CISA/NVD/GHSA;
 *   we only keep agent-relevant NET-NEW CVEs (unless --force).
 *
 * DETECTION READINESS
 *   KEV entries are metadata (no payload), so detection_ready is almost always
 *   false. We set it true ONLY when the NVD description / exploit reference
 *   text contains payload-like content (fenced code, curl, payload:, <script>,
 *   etc). The full description + exploit references go into
 *   `_vulncheck_sync.advisory_body` -- the single payload source the
 *   downstream promote-detection-ready.ts crystalliser reads.
 *
 * SECRET DISCIPLINE (hard rule)
 *   The API key is read ONLY from process.env.VULNCHECK_API_KEY. There is NO
 *   --key CLI flag. The key is never echoed. Missing key => helpful message +
 *   exit 2 (recoverable). A free community key is available at vulncheck.com.
 *
 * API SHAPE (verified from docs + vulncheck-oss/sdk-go, 2026-06)
 *   Base:   https://api.vulncheck.com/v3
 *   Auth:   Authorization: Bearer <token>
 *   Index:  GET /v3/index/{name}?page=&limit=&cve=
 *           name = "vulncheck-kev" | "nist-nvd2"
 *   Envelope: { _benchmark, _meta: { total_documents, page, total_pages,
 *             next_cursor, limit, ... }, data: [ ...records ] }
 *   KEV record: { vendorProject, product, shortDescription, vulnerabilityName,
 *             cve: string[], cwes: string[],
 *             vulncheck_xdb: [{ xdb_url, exploit_type, ... }],
 *             vulncheck_reported_exploitation: [{ url, date_added }],
 *             date_added }
 *   NVD++ record: raw NVD 2.0 CVE object. We accept BOTH the unwrapped shape
 *             ({ id, descriptions[], references[], weaknesses[], metrics }) and
 *             a { cve: {...} } wrapped shape, defensively, since we could not
 *             live-verify nist-nvd2 without a key.
 *   Rate limit: community tier 1000 req/min. We pace politely well under that.
 *
 * ASSUMPTIONS DOCUMENTED (no live key to verify against)
 *   - Pagination via _meta.page / _meta.total_pages and _meta.next_cursor.
 *     We prefer next_cursor when present, else increment page.
 *   - KEV `cwes` is an array of "CWE-NNN" strings; NVD weaknesses carry
 *     "CWE-NNN" in description[].value. Both normalised by extractCwes().
 *   - We default the KEV scan to a single page bounded by --limit to keep the
 *     dry-run cheap; the firehose page walk stops at MAX_PAGES.
 *
 * Usage:
 *   npx tsx scripts/sync-vulncheck.ts                 # dry-run
 *   npx tsx scripts/sync-vulncheck.ts --write         # write proposals
 *   npx tsx scripts/sync-vulncheck.ts --force         # overwrite existing
 *   npx tsx scripts/sync-vulncheck.ts --verbose
 *   npx tsx scripts/sync-vulncheck.ts --limit 50      # cap output
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path (recoverable -- e.g. VULNCHECK_API_KEY not set)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "vulncheck");

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

// ---------------------------------------------------------------------------
// Secret discipline: key from env ONLY. No --key flag. Never echoed.
// ---------------------------------------------------------------------------
const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;

const API_BASE = "https://api.vulncheck.com/v3";
const USER_AGENT =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// Community tier is 1000 req/min. We pace far under that. Per-request paging is
// the only loop, so a small inter-page delay is plenty.
const PAGE_DELAY_MS = 250;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Bound the firehose page walk so a missing/odd _meta can never spin forever.
const MAX_PAGES = 25;
// Per-index cap on raw records pulled before filtering. Keeps the dry-run and
// daily cron cheap; agent-relevant CVEs are a tiny fraction of the corpus.
const PER_INDEX_RECORD_CAP = 2000;

// ---------------------------------------------------------------------------
// Allowlist + agent-relevance gate (mirrors sync-ghsa.ts contract).
// ---------------------------------------------------------------------------

// Agent package allowlist (NOT ML infra). Used to match a CVE's affected
// product / CPE / vendor text. Kept in sync with sync-ghsa.ts AI_PACKAGES.
const AI_PACKAGE_NAMES: string[] = [
  // pip
  "langchain",
  "langchain-core",
  "langchain-community",
  "langchain-experimental",
  "langgraph",
  "langsmith",
  "llama-index",
  "llama-index-core",
  "llama_index",
  "openai",
  "anthropic",
  "dspy",
  "dspy-ai",
  "autogen-agentchat",
  "pyautogen",
  "autogen",
  "crewai",
  "crew-ai",
  "litellm",
  "semantic-kernel",
  "semantic_kernel",
  "pyrit",
  "garak",
  "promptfoo",
  "llm-guard",
  "nemoguardrails",
  "nemo-guardrails",
  "guardrails-ai",
  "pydantic-ai",
  "haystack-ai",
  "haystack",
  "instructor",
  "ollama",
  "embedchain",
  "mcp",
  "fastmcp",
  "modelcontextprotocol",
  "model-context-protocol",
  // npm
  "@langchain/core",
  "@langchain/community",
  "@langchain/openai",
  "@langchain/anthropic",
  "@anthropic-ai/sdk",
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/inspector",
  "llamaindex",
  "@google/genai",
  "@aws-sdk/client-bedrock-runtime",
  // jvm / nuget / go / ruby
  "langchain4j",
  "openai-gpt3-java",
  "microsoft.semantickernel",
  "langchaingo",
  "go-openai",
  "langchainrb",
  "ruby-openai",
  // common product / vendor naming seen in CPE for agent runtimes
  "anythingllm",
  "anything-llm",
  "flowise",
  "dify",
  "open-webui",
  "openwebui",
];

// Tokenised package-shape regex: lets a NEW agent package self-onboard even if
// not in the explicit list. agentRelevance() is still the final gate. Mirrors
// sync-ghsa.ts AGENT_PACKAGE_RX (minus the bare "agent"/"llm" tokens, which we
// only allow inside the bounded delimiters to avoid "user agent" false hits).
const AGENT_PACKAGE_RX =
  /(?:^|[-_/@.\s])(?:langchain|langgraph|llama[-_]?index|llamaindex|mcp|fastmcp|modelcontextprotocol|model[-_]context[-_]protocol|crew[-_]?ai|autogen|pyautogen|semantic[-_]kernel|pydantic[-_]ai|haystack|dspy|embedchain|litellm|guardrails?|llm[-_]?guard|nemoguardrails|agentscope|smolagents|agno|anythingllm|flowise|open[-_]?webui|dify)(?:[-_/@.\s]|$)/i;

// CWE -> ATR category (mirror of sync-ghsa.ts CWE_TO_CATEGORY).
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
  for (const c of cwes) if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  return "model-abuse";
}

// Agent-runtime CWEs (mirror of sync-ghsa.ts AGENT_RELEVANT_CWES). Memory-
// safety / availability CWEs are deliberately excluded.
const AGENT_RELEVANT_CWES = new Set([
  "CWE-94",
  "CWE-95",
  "CWE-77",
  "CWE-78",
  "CWE-917",
  "CWE-1336",
  "CWE-918",
  "CWE-22",
  "CWE-23",
  "CWE-611",
  "CWE-502",
  "CWE-89",
  "CWE-79",
  "CWE-74",
  "CWE-470",
  "CWE-601",
  "CWE-862",
  "CWE-863",
  "CWE-200",
  "CWE-20",
]);

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
  /untrusted (input|data|manifest|model|content)/,
];

// Normalised CVE shape both feeds produce.
interface VcCve {
  cve_id: string;
  source: "vulncheck-kev" | "nist-nvd2";
  title: string;
  description: string;
  cwes: string[];
  severity: "critical" | "high" | "medium" | "low";
  references: string[]; // exploit + general references
  exploit_references: string[]; // KEV xdb / reported-exploitation urls
  affected_products: string[]; // vendor/product/cpe strings for allowlist match
  kev_exploited: boolean; // present in VulnCheck KEV (exploited-in-wild)
  ransomware: boolean;
  date_added: string | null;
  raw_excerpt: string; // provenance: a trimmed raw record dump
}

// Gate 1: does this CVE touch an allowlisted agent package?
function matchesAllowlist(cve: VcCve): { ok: boolean; reason: string } {
  const hay = [
    ...cve.affected_products,
    cve.title,
    cve.description,
  ]
    .join(" \n ")
    .toLowerCase();
  for (const name of AI_PACKAGE_NAMES) {
    // word-ish boundary so "openai" does not match "openair"; we surround the
    // package token with delimiter/边界 checks.
    const rx = new RegExp(
      `(?:^|[^a-z0-9])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:[^a-z0-9]|$)`,
      "i",
    );
    if (rx.test(hay)) return { ok: true, reason: `allowlist package ${name}` };
  }
  if (AGENT_PACKAGE_RX.test(hay))
    return { ok: true, reason: "agent-package-shape name" };
  return {
    ok: false,
    reason: "no allowlisted agent package in affected products/description",
  };
}

// Gate 2: agent-runtime relevance (mirror of sync-ghsa.ts agentRelevance).
export function agentRelevance(cve: {
  description?: string;
  title?: string;
  cwes?: string[];
}): { relevant: boolean; reason: string } {
  const cwes = cve.cwes ?? [];
  const hitCwe = cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const body = `${cve.title ?? ""}\n${cve.description ?? ""}`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  return {
    relevant: false,
    reason: `no agent-relevant CWE or keyword (cwes: ${cwes.join(",") || "none"})`,
  };
}

// ---------------------------------------------------------------------------
// HTTP.
// ---------------------------------------------------------------------------

interface IndexMeta {
  total_documents?: number;
  page?: number;
  total_pages?: number;
  next_cursor?: string;
  limit?: number;
}
interface IndexEnvelope {
  _meta?: IndexMeta;
  data?: unknown[];
}

async function fetchIndexPage(
  name: string,
  page: number,
  cursor: string | null,
  perPage: number,
): Promise<IndexEnvelope> {
  const u = new URL(`${API_BASE}/index/${name}`);
  u.searchParams.set("limit", String(perPage));
  if (cursor) u.searchParams.set("cursor", cursor);
  else u.searchParams.set("page", String(page));

  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": USER_AGENT,
    // Key never logged; only used here.
    Authorization: `Bearer ${VULNCHECK_API_KEY}`,
  };

  const res = await fetch(u.toString(), { headers });
  if (res.status === 401 || res.status === 403) {
    // Key invalid / unauthorised. Recoverable: user must fix the key.
    console.error(
      `VulnCheck auth failed (${res.status}). The VULNCHECK_API_KEY is ` +
        "missing or invalid. Set a valid community key (free at vulncheck.com).",
    );
    process.exit(2);
  }
  if (res.status === 429) {
    console.error(
      "VulnCheck rate limit hit (429). Community tier is 1000 req/min; " +
        "the daily cron will retry. Exiting recoverable.",
    );
    process.exit(2);
  }
  if (!res.ok) {
    throw new Error(
      `VulnCheck index ${name} page ${page} failed: ${res.status} ${res.statusText}`,
    );
  }
  const json = (await res.json()) as IndexEnvelope;
  if (typeof json !== "object" || json === null || !Array.isArray(json.data)) {
    throw new Error(
      `VulnCheck index ${name} returned an unexpected envelope (no data[]). ` +
        "API schema may have changed.",
    );
  }
  return json;
}

// Walk pages of an index, applying the keep predicate as records arrive so we
// can stop early once enough agent-relevant CVEs are collected.
async function walkIndex(
  name: string,
  perPage: number,
  parse: (rec: unknown) => VcCve | null,
): Promise<VcCve[]> {
  const out: VcCve[] = [];
  let page = 1;
  let cursor: string | null = null;
  let pulled = 0;
  for (let i = 0; i < MAX_PAGES; i++) {
    let env: IndexEnvelope;
    try {
      env = await fetchIndexPage(name, page, cursor, perPage);
    } catch (e) {
      if (VERBOSE) console.error(`  ${name} page ${page} error: ${e}`);
      break;
    }
    const data = env.data ?? [];
    if (data.length === 0) break;
    for (const rec of data) {
      pulled += 1;
      const parsed = parse(rec);
      if (parsed) out.push(parsed);
    }
    if (VERBOSE)
      console.error(
        `  ${name}: page ${page} pulled ${data.length} (kept-so-far ${out.length}, total seen ${pulled})`,
      );
    if (pulled >= PER_INDEX_RECORD_CAP) break;
    // Stop once we have comfortably more agent-relevant candidates than LIMIT.
    if (Number.isFinite(LIMIT) && out.length >= LIMIT * 3) break;

    const meta = env._meta ?? {};
    if (meta.next_cursor) {
      cursor = meta.next_cursor;
    } else if (
      typeof meta.page === "number" &&
      typeof meta.total_pages === "number"
    ) {
      if (meta.page >= meta.total_pages) break;
      page = meta.page + 1;
      cursor = null;
    } else {
      // No usable pagination info -> single page only.
      break;
    }
    await sleep(PAGE_DELAY_MS);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Record parsers.
// ---------------------------------------------------------------------------

function normSeverity(
  s: string | undefined | null,
): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v === "high") return "high";
  if (v === "medium" || v === "moderate") return "medium";
  if (v === "low") return "low";
  return "high"; // KEV entries are exploited; bias up when unknown.
}

function extractCwes(input: unknown): string[] {
  const out = new Set<string>();
  const push = (s: unknown) => {
    if (typeof s !== "string") return;
    const m = s.match(/CWE-\d+/i);
    if (m) out.add(m[0].toUpperCase());
  };
  if (Array.isArray(input)) for (const x of input) push(x);
  else push(input);
  return [...out];
}

interface KevRecord {
  vendorProject?: string;
  product?: string;
  shortDescription?: string;
  vulnerabilityName?: string;
  cve?: string[] | string;
  cwes?: string[] | string;
  knownRansomwareCampaignUse?: string;
  vulncheck_xdb?: Array<{ xdb_url?: string; exploit_type?: string }>;
  vulncheck_reported_exploitation?: Array<{ url?: string }>;
  date_added?: string;
}

function parseKev(rec: unknown): VcCve | null {
  if (typeof rec !== "object" || rec === null) return null;
  const k = rec as KevRecord;
  const cveArr = Array.isArray(k.cve) ? k.cve : k.cve ? [k.cve] : [];
  const cveId = cveArr.find((c) => /^CVE-\d{4}-\d+$/i.test(c));
  if (!cveId) return null; // CVE id is our primary key; skip CVE-less rows.

  const xdbUrls = (k.vulncheck_xdb ?? [])
    .map((x) => x?.xdb_url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
  const reportedUrls = (k.vulncheck_reported_exploitation ?? [])
    .map((x) => x?.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);

  const affected = [k.vendorProject, k.product].filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );

  return {
    cve_id: cveId.toUpperCase(),
    source: "vulncheck-kev",
    title: (k.vulnerabilityName || k.product || cveId).toString().trim(),
    description: (k.shortDescription || "").toString().trim(),
    cwes: extractCwes(k.cwes),
    severity: "high", // KEV = exploited in wild; no severity field on KEV rows.
    references: [...reportedUrls],
    exploit_references: [...xdbUrls, ...reportedUrls],
    affected_products: affected,
    kev_exploited: true,
    ransomware: /known/i.test(k.knownRansomwareCampaignUse || ""),
    date_added: k.date_added || null,
    raw_excerpt: JSON.stringify(
      {
        vendorProject: k.vendorProject,
        product: k.product,
        shortDescription: k.shortDescription,
        cwes: k.cwes,
        xdb: xdbUrls.slice(0, 5),
      },
      null,
      2,
    ),
  };
}

// NVD 2.0 record. VulnCheck nist-nvd2 mirrors NVD 2.0. We accept both the raw
// CVE object and a { cve: {...} } wrapper defensively.
interface NvdCveObj {
  id?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  references?: Array<{ url?: string; tags?: string[] }>;
  weaknesses?: Array<{ description?: Array<{ value?: string }> }>;
  metrics?: {
    cvssMetricV31?: Array<{ cvssData?: { baseSeverity?: string } }>;
    cvssMetricV30?: Array<{ cvssData?: { baseSeverity?: string } }>;
    cvssMetricV2?: Array<{ baseSeverity?: string }>;
  };
  configurations?: unknown;
}

function nvdSeverity(m: NvdCveObj["metrics"]): string | null {
  if (!m) return null;
  return (
    m.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
    m.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
    m.cvssMetricV2?.[0]?.baseSeverity ??
    null
  );
}

// Pull CPE product strings out of an NVD configurations tree (best-effort).
function cpeProductsFromConfig(cfg: unknown, acc: string[], depth = 0): void {
  if (depth > 8 || cfg == null) return;
  if (Array.isArray(cfg)) {
    for (const x of cfg) cpeProductsFromConfig(x, acc, depth + 1);
    return;
  }
  if (typeof cfg === "object") {
    const o = cfg as Record<string, unknown>;
    if (typeof o.criteria === "string") acc.push(o.criteria);
    for (const v of Object.values(o)) cpeProductsFromConfig(v, acc, depth + 1);
  }
}

function parseNvd(rec: unknown): VcCve | null {
  if (typeof rec !== "object" || rec === null) return null;
  const wrapped = rec as { cve?: NvdCveObj };
  const c: NvdCveObj =
    wrapped.cve && typeof wrapped.cve === "object"
      ? wrapped.cve
      : (rec as NvdCveObj);
  const cveId = c.id;
  if (typeof cveId !== "string" || !/^CVE-\d{4}-\d+$/i.test(cveId)) return null;

  const desc =
    (c.descriptions ?? []).find((d) => d.lang === "en")?.value ??
    (c.descriptions ?? [])[0]?.value ??
    "";
  const refs = (c.references ?? [])
    .map((r) => r?.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
  const exploitRefs = (c.references ?? [])
    .filter((r) =>
      (r?.tags ?? []).some((t) => /exploit|poc|proof/i.test(String(t))),
    )
    .map((r) => r?.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
  const cwes = extractCwes(
    (c.weaknesses ?? []).flatMap((w) =>
      (w.description ?? []).map((d) => d.value),
    ),
  );

  const cpeProducts: string[] = [];
  cpeProductsFromConfig(c.configurations, cpeProducts);

  return {
    cve_id: cveId.toUpperCase(),
    source: "nist-nvd2",
    title: cveId,
    description: desc.toString().trim(),
    cwes,
    severity: normSeverity(nvdSeverity(c.metrics)),
    references: refs,
    exploit_references: exploitRefs,
    affected_products: cpeProducts.slice(0, 50),
    kev_exploited: false,
    ransomware: false,
    date_added: null,
    raw_excerpt: JSON.stringify(
      {
        id: cveId,
        description: desc.slice(0, 400),
        cwes,
        severity: nvdSeverity(c.metrics),
      },
      null,
      2,
    ),
  };
}

// ---------------------------------------------------------------------------
// Detection readiness.
// ---------------------------------------------------------------------------

const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "## *Proof of Concept",
    "## *Reproducer",
    "## *Exploit",
    "payload:",
    "curl ",
    "POST \\/[a-z]",
    "GET \\/[a-z]",
    "<script>",
    "\\$\\{",
    "prompt: ['\"]",
  ].join("|"),
  "im",
);

function isDetectionReady(cve: VcCve): { ready: boolean; reason: string } {
  const body = `${cve.title}\n${cve.description}`;
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return { ready: true, reason: "payload-like content in description" };
  if (cve.exploit_references.length > 0)
    return {
      ready: true,
      reason: `exploit reference present (${cve.exploit_references.length})`,
    };
  return {
    ready: false,
    reason: "KEV/NVD metadata only -- no reproducer / payload (typical for KEV)",
  };
}

// ---------------------------------------------------------------------------
// Idempotency.
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

function buildKnownIndex(): { cves: Set<string> } {
  const cves = new Set<string>();
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
      const refs = (doc as { references?: { cve?: string[] | string } })
        ?.references;
      if (refs?.cve) {
        const v = refs.cve;
        if (typeof v === "string") cves.add(v.toUpperCase());
        else if (Array.isArray(v))
          for (const c of v)
            if (typeof c === "string") cves.add(c.toUpperCase());
      }
    }
  }
  return { cves };
}

// ---------------------------------------------------------------------------
// Proposal renderer (mirrors sync-huntr / sync-ghsa field-by-field).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(cve: VcCve): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const category = guessCategory(cve.cwes);
  const triage = isDetectionReady(cve);
  const responseActions =
    cve.severity === "critical" || cve.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = `  cve:\n    - "${cve.cve_id}"\n`;
  const cweBlock =
    cve.cwes.length > 0
      ? `  cwe:\n${cve.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const allRefs = [...new Set([...cve.references, ...cve.exploit_references])];
  const externalBlock =
    allRefs.length > 0
      ? `  external:\n${allRefs.map((u) => `    - "${u}"`).join("\n")}\n`
      : "";

  // Advisory body for the crystalliser: description + exploit references +
  // a raw record excerpt. This is the SINGLE payload source downstream.
  const advisoryBody =
    `${cve.description || "(no description provided by VulnCheck)"}\n\n` +
    (cve.exploit_references.length
      ? `Exploit references:\n${cve.exploit_references.map((u) => `- ${u}`).join("\n")}\n\n`
      : "") +
    `Raw record excerpt:\n${cve.raw_excerpt}`;

  const title = cve.title.replace(/"/g, '\\"').slice(0, 120);
  const descLine = (cve.description || cve.title)
    .replace(/\n+/g, " ")
    .trim()
    .slice(0, 600);

  return `# ATR rule proposal -- generated by scripts/sync-vulncheck.ts
# Source: VulnCheck ${cve.source}${cve.kev_exploited ? " (known-exploited / KEV)" : ""}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${cve.cve_id}
rule_version: 1
status: draft
description: >
  VulnCheck ${cve.source}${cve.kev_exploited ? " known-exploited" : ""} CVE ${cve.cve_id}.
  ${descLine}
author: "ATR Community (VulnCheck sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${cve.severity}

references:
${cveBlock}${cweBlock}${externalBlock}
metadata_provenance:
  vulncheck: vulncheck-sync
  cve: vulncheck-sync
${cve.cwes.length ? "  cwe: vulncheck-sync\n" : ""}
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
    # TODO(human): convert the VulnCheck advisory body / exploit reference
    # below into precision-safe detection.conditions regex/string matchers.
    # Empty until promoted to rules/. See _vulncheck_sync.advisory_body for
    # the full text.
    #
    # === advisory excerpt ===
${
    cve.description
      .split("\n")
      .filter((s) => s.trim().length > 0)
      .slice(0, 40)
      .map((s) => `    # ${s}`)
      .join("\n") || "    # (no description body in source)"
  }
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

# === sync-vulncheck.ts provenance ===
_vulncheck_sync:
  cve_id: "${cve.cve_id}"
  feed: "${cve.source}"
  kev_exploited_in_wild: ${cve.kev_exploited}
  known_ransomware_use: ${cve.ransomware}
  cwes: ${JSON.stringify(cve.cwes)}
  affected_products: ${JSON.stringify(cve.affected_products.slice(0, 20))}
  exploit_references: ${JSON.stringify(cve.exploit_references)}
  date_added: ${cve.date_added ? `"${cve.date_added}"` : "null"}
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(advisoryBody, "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  kev_pulled: number;
  nvd_pulled: number;
  passed_allowlist: number;
  filtered_not_agent: number;
  filtered_not_allowlisted: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  kev_exploited_new: number;
  written_files: string[];
  errors: string[];
}

function emitSummary(summary: RunSummary): void {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::vulncheck-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      kev_exploited_new: summary.kev_exploited_new,
      passed_allowlist: summary.passed_allowlist,
      filtered_not_agent: summary.filtered_not_agent,
      filtered_not_allowlisted: summary.filtered_not_allowlisted,
      already_known: summary.already_known,
      kev_pulled: summary.kev_pulled,
      nvd_pulled: summary.nvd_pulled,
    })}`,
  );
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    kev_pulled: 0,
    nvd_pulled: 0,
    passed_allowlist: 0,
    filtered_not_agent: 0,
    filtered_not_allowlisted: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    kev_exploited_new: 0,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-vulncheck.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  // Secret discipline: key from env ONLY. Missing -> exit 2 (recoverable).
  if (!VULNCHECK_API_KEY) {
    console.error(
      "VULNCHECK_API_KEY env var not set. This source needs a VulnCheck " +
        "community API token (free at vulncheck.com). Set VULNCHECK_API_KEY " +
        "in the environment and re-run. No --key flag is accepted by design " +
        "(secret discipline).",
    );
    summary.errors.push("VULNCHECK_API_KEY not set");
    emitSummary(summary);
    process.exit(2);
  }

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();

  // Pull both feeds. KEV first (the exploited-in-wild signal we most want).
  let candidates: VcCve[] = [];
  try {
    const kev = await walkIndex("vulncheck-kev", 200, parseKev);
    summary.kev_pulled = kev.length;
    candidates.push(...kev);
  } catch (e) {
    summary.errors.push(`vulncheck-kev: ${(e as Error).message}`);
    if (VERBOSE) console.error(`vulncheck-kev error: ${e}`);
  }
  try {
    const nvd = await walkIndex("nist-nvd2", 200, parseNvd);
    summary.nvd_pulled = nvd.length;
    candidates.push(...nvd);
  } catch (e) {
    summary.errors.push(`nist-nvd2: ${(e as Error).message}`);
    if (VERBOSE) console.error(`nist-nvd2 error: ${e}`);
  }

  if (candidates.length === 0 && summary.errors.length > 0) {
    // Both feeds failed for non-auth reasons (auth already exited 2 above).
    console.error("no data pulled from either VulnCheck feed.");
    emitSummary(summary);
    process.exit(summary.errors.some((e) => /schema/.test(e)) ? 1 : 2);
  }

  // Merge KEV + NVD on CVE id: prefer KEV's exploited flag, prefer the richer
  // (longer) description, union references/cwes. KEV is processed first so its
  // entry seeds the map.
  const merged = new Map<string, VcCve>();
  for (const c of candidates) {
    const existing = merged.get(c.cve_id);
    if (!existing) {
      merged.set(c.cve_id, c);
      continue;
    }
    merged.set(c.cve_id, {
      ...existing,
      kev_exploited: existing.kev_exploited || c.kev_exploited,
      ransomware: existing.ransomware || c.ransomware,
      description:
        c.description.length > existing.description.length
          ? c.description
          : existing.description,
      cwes: [...new Set([...existing.cwes, ...c.cwes])],
      references: [...new Set([...existing.references, ...c.references])],
      exploit_references: [
        ...new Set([...existing.exploit_references, ...c.exploit_references]),
      ],
      affected_products: [
        ...new Set([...existing.affected_products, ...c.affected_products]),
      ],
      date_added: existing.date_added ?? c.date_added,
    });
  }

  let writtenCount = 0;
  for (const cve of merged.values()) {
    if (writtenCount >= LIMIT) break;

    // Gate 1: agent-package allowlist.
    const allow = matchesAllowlist(cve);
    if (!allow.ok) {
      summary.filtered_not_allowlisted += 1;
      if (VERBOSE)
        console.error(`  drop (not-allowlisted) ${cve.cve_id}: ${allow.reason}`);
      continue;
    }
    // Gate 2: agent-runtime relevance.
    const rel = agentRelevance(cve);
    if (!rel.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(`  drop (not-agent) ${cve.cve_id}: ${rel.reason}`);
      continue;
    }
    summary.passed_allowlist += 1;

    // Dedup: CVE id is the cross-source primary key.
    if (!FORCE && known.cves.has(cve.cve_id)) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-rule ${cve.cve_id}: already covered`);
      continue;
    }
    const outName = `${cve.cve_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    const triage = isDetectionReady(cve);
    const body = renderProposal(cve);

    // Self-verify a sample parses as YAML in dry-run (contract step).
    if (!WRITE && writtenCount === 0) {
      try {
        yaml.load(body);
        console.error(`  [self-check] sample proposal ${outName} parses OK`);
      } catch (e) {
        console.error(`  [self-check] FAILED to parse ${outName}: ${e}`);
      }
    }

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(
        `  would write ${outName}` +
          `${cve.kev_exploited ? " [KEV-exploited]" : ""}` +
          ` (detection_ready=${triage.ready})`,
      );
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    if (cve.kev_exploited) summary.kev_exploited_new += 1;
    writtenCount += 1;
  }

  emitSummary(summary);
  process.exit(0);
}

// Run only when invoked directly (not when imported for tests).
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
