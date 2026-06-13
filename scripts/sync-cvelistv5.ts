#!/usr/bin/env npx tsx
/**
 * sync-cvelistv5.ts
 *
 * Pulls the MITRE CVE Program cvelistV5 firehose -- the CNA-layer source
 * where EVERY CNA's CVEs land ~7 minutes after assignment, BEFORE they
 * propagate to NVD -- and emits ATR rule proposals under
 * proposals/cvelistv5/<CVE-id>.proposal.yaml.
 *
 * Why this source on top of GHSA/NVD/OSV:
 *   - It is the earliest public signal (CNA publish -> ~7 min -> here, vs
 *     hours/days to NVD). For an agent-security standard, catching an
 *     AI-CNA's fresh CVE first is the net-new value.
 *   - It covers CNAs that never publish to GHSA (e.g. HiddenLayer, Wiz,
 *     JFrog, NVIDIA, Cisco, IBM, Elastic, Google as a CNA).
 *   - Heavy overlap with GHSA/NVD is EXPECTED; dedup by CVE id against
 *     rules/ + proposals/ keeps it net-additive only.
 *
 * Data source (verified live 2026-06-12):
 *   Delta feed (daily driver):
 *     https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json
 *     Real shape:
 *       {
 *         "fetchTime": "2026-06-12T03:26:45.354Z",
 *         "numberOfChanges": 11,
 *         "new":     [ { cveId, cveOrgLink, githubLink, dateUpdated }, ... ],
 *         "updated": [ { cveId, cveOrgLink, githubLink, dateUpdated }, ... ]
 *       }
 *     githubLink already points at the raw record URL, so we follow it
 *     directly; we also derive the path from the CVE id as a fallback.
 *
 *   Full records (CVE Record Format 5.x):
 *     raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<YEAR>/<bucket>xxx/CVE-<YEAR>-<N>.json
 *     bucket = the CVE number with the last 3 digits replaced by "xxx",
 *     e.g. CVE-2026-47366 -> cves/2026/47xxx/CVE-2026-47366.json,
 *          CVE-2026-12345 -> cves/2026/12xxx/CVE-2026-12345.json,
 *          CVE-2026-1234  -> cves/2026/1xxx/CVE-2026-1234.json.
 *     Record fields used:
 *       cveMetadata.assignerShortName / state / datePublished
 *       containers.cna.title
 *       containers.cna.descriptions[].value
 *       containers.cna.affected[] (vendor / product / packageName / cpes)
 *       containers.cna.references[].url
 *       containers.cna.problemTypes[].descriptions[].cweId
 *
 * AI relevance (TWO independent admit paths, then ONE common gate):
 *   A CVE is considered for proposal if EITHER
 *     (a) cveMetadata.assignerShortName is in AI_CNA_SHORTNAMES (the set of
 *         CNAs whose remit is AI/security tooling), OR
 *     (b) the AI_PACKAGES allowlist matches an affected product/packageName,
 *   ...AND then -- in BOTH cases -- it must clear agentRelevance() (the
 *   CWE + keyword gate ported from sync-ghsa.ts). An AI CNA alone is NOT
 *   enough: huntr/Protect AI mints plenty of non-agent ML CVEs, and ATR's
 *   scope is agent-runtime threats only. The agentRelevance gate also keeps
 *   ML-infra CVEs (tensorflow/torch/vllm/ray/mlflow/gradio/...) out even when
 *   an AI CNA assigned them.
 *
 * Modes:
 *   daily (default): read delta.json once (new + updated).
 *   backfill: --days N walks delta.json AND recent records. cvelistV5's
 *     delta.json is a rolling snapshot (only the most recent change set), so
 *     true historical backfill would require cloning the repo. We approximate
 *     by (1) honoring --days as a publish-date floor applied to every record
 *     we fetch, and (2) draining both delta.new and delta.updated. Records
 *     whose datePublished is older than the floor are skipped. Default 7.
 *
 * Idempotency: skip if the CVE id already exists in rules/ or proposals/
 * (buildKnownIndex), unless --force. CVE id is the cross-source primary key.
 *
 * Usage:
 *   npx tsx scripts/sync-cvelistv5.ts                     # dry-run, delta feed
 *   npx tsx scripts/sync-cvelistv5.ts --write             # write proposals
 *   npx tsx scripts/sync-cvelistv5.ts --days 14 --verbose # wider window
 *   npx tsx scripts/sync-cvelistv5.ts --limit 5 --verbose # cap + dry-run
 *   npx tsx scripts/sync-cvelistv5.ts --force             # overwrite existing
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path available (recoverable; e.g. delta.json unreachable)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "cvelistv5");

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
const DAYS = opt("--days") ? parseInt(opt("--days")!, 10) : 7;

const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

const DELTA_URL =
  "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json";
const RAW_BASE =
  "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves";

// ---------------------------------------------------------------------------
// AI-CNA shortName set. VERIFIED against
// https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json
// (grepped raw, 2026-06-12). Exact strings matter -- several differ in case
// from the org name:
//   '@huntr_ai'  = Protect AI (formerly huntr.dev)
//   'Wiz'        = Wiz, Inc.
//   'JFrog'      = JFrog
//   'snyk'       = Snyk
//   'GitHub_M'   = GitHub, Inc.   (the "M" advisory CNA; GitHub_P is products)
//   'HiddenLayer'= HiddenLayer, Inc.
//   'nvidia'     = NVIDIA Corporation        (lowercase!)
//   'ibm'        = IBM Corporation           (lowercase!)
//   'cisco'      = Cisco Systems, Inc.       (lowercase!)
//   'Google'     = Google LLC                (NOT google_android / GoogleCloud)
//   'elastic'    = Elastic                   (lowercase!)
// Match is case-insensitive in code (cveMetadata.assignerShortName casing has
// drifted historically), but we store the canonical strings for provenance.
const AI_CNA_SHORTNAMES = new Set(
  [
    "@huntr_ai",
    "Wiz",
    "JFrog",
    "snyk",
    "GitHub_M",
    "HiddenLayer",
    "nvidia",
    "ibm",
    "cisco",
    "Google",
    "elastic",
  ].map((s) => s.toLowerCase()),
);

// AI AGENT package allowlist (ported verbatim from sync-ghsa.ts). SCOPE: agent
// frameworks + agent infra/protocol + runtime guardrails + LLM IO SDKs.
// Intentionally EXCLUDES ML infra (tensorflow / torch / onnxruntime / gradio /
// mlflow / ray / diffusers / datasets / accelerate / huggingface-hub /
// transformers / vllm). For cvelistV5 we match these tokens against the
// affected[] vendor/product/packageName/cpes -- the CVE 5.x affected block is
// far less structured than GHSA's, so we match as bounded substrings.
const AI_PACKAGE_TOKENS = [
  // pip / python
  "langchain",
  "langchain-core",
  "langchain-community",
  "langchain-experimental",
  "langgraph",
  "langsmith",
  "llama-index",
  "llama_index",
  "llamaindex",
  "llama-index-core",
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
  "semantickernel",
  "pyrit",
  "garak",
  "promptfoo",
  "llm-guard",
  "nemoguardrails",
  "nemo-guardrails",
  "guardrails-ai",
  "pydantic-ai",
  "haystack-ai",
  "instructor",
  "ollama",
  "embedchain",
  "fastmcp",
  // npm / scoped
  "@langchain/core",
  "@langchain/community",
  "@langchain/openai",
  "@langchain/anthropic",
  "@anthropic-ai/sdk",
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/inspector",
  "modelcontextprotocol",
  "model context protocol",
  "@vercel/ai",
  "@ai-sdk/openai",
  "@ai-sdk/anthropic",
  // maven / nuget / go / rubygems
  "langchain4j",
  "openai-gpt3-java",
  "microsoft.semantickernel",
  "langchaingo",
  "go-openai",
  "langchainrb",
  "ruby-openai",
] as const;

// Bounded MCP token: bare "mcp" matched as a whole token only (avoids matching
// "mcpu", "mcpe", random vendor strings). The leading/trailing boundary class
// covers package separators commonly seen in product/packageName/cpe strings.
const MCP_TOKEN_RX = /(?:^|[-_/@.\s:])mcp(?:[-_/@.\s:]|$)/i;

// CWE -> ATR category (ported verbatim from sync-ghsa.ts).
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

// Agent-relevant CWEs (ported verbatim from sync-ghsa.ts).
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

// Agent-threat keyword phrases (ported verbatim from sync-ghsa.ts).
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

// Second gate (after the admit path): is this a CVE ATR could write an
// agent-runtime detection for? Same logic as sync-ghsa.ts agentRelevance.
function agentRelevance(input: {
  summary?: string;
  description?: string;
  cwes?: string[];
}): { relevant: boolean; reason: string } {
  const cwes = input.cwes ?? [];
  const hitCwe = cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const body = `${input.summary ?? ""}\n${input.description ?? ""}`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  return {
    relevant: false,
    reason: `no agent-relevant CWE or keyword (cwes: ${cwes.join(",") || "none"})`,
  };
}

// ---------------------------------------------------------------------------
// CVE 5.x record types (only the fields we read).
// ---------------------------------------------------------------------------

interface DeltaItem {
  cveId: string;
  cveOrgLink?: string;
  githubLink?: string;
  dateUpdated?: string;
}
interface DeltaFeed {
  fetchTime?: string;
  numberOfChanges?: number;
  new?: DeltaItem[];
  updated?: DeltaItem[];
}

interface CveAffected {
  vendor?: string;
  product?: string;
  packageName?: string;
  collectionURL?: string;
  cpes?: string[];
}
interface CveDescription {
  lang?: string;
  value?: string;
}
interface CveReference {
  url?: string;
  tags?: string[];
}
interface CveProblemTypeDesc {
  type?: string;
  cweId?: string;
  description?: string;
}
interface CveRecord {
  cveMetadata?: {
    cveId?: string;
    state?: string;
    assignerShortName?: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers?: {
    cna?: {
      title?: string;
      descriptions?: CveDescription[];
      affected?: CveAffected[];
      references?: CveReference[];
      problemTypes?: Array<{ descriptions?: CveProblemTypeDesc[] }>;
    };
  };
}

// Normalized view we pass to the renderer.
interface CveSummary {
  cve_id: string;
  assigner: string;
  title: string;
  description: string;
  cwes: string[];
  severity: "critical" | "high" | "medium" | "low";
  affected_strings: string[]; // human-readable vendor:product / packageName
  references: string[];
  published_at: string | null;
  admit_path: "ai-cna" | "package-allowlist";
}

// ---------------------------------------------------------------------------
// Record URL derivation. bucket = number with last 3 digits -> "xxx".
// ---------------------------------------------------------------------------

function recordUrlForCve(cveId: string): string | null {
  const m = cveId.match(/^CVE-(\d{4})-(\d+)$/);
  if (!m) return null;
  const year = m[1];
  const num = m[2];
  // bucket: drop the last 3 digits; if <= 3 digits, bucket is "0xxx".
  const bucket = num.length <= 3 ? "0" : num.slice(0, num.length - 3);
  return `${RAW_BASE}/${year}/${bucket}xxx/${cveId}.json`;
}

async function fetchJson<T>(url: string): Promise<T | null> {
  const res = await fetch(url, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok) {
    if (VERBOSE) console.error(`  fetch ${res.status} ${url}`);
    return null;
  }
  return (await res.json()) as T;
}

async function fetchRecord(item: DeltaItem): Promise<CveRecord | null> {
  // Prefer the githubLink the feed gives us; fall back to derived path.
  const urls = [item.githubLink, recordUrlForCve(item.cveId)].filter(
    (u): u is string => typeof u === "string" && u.length > 0,
  );
  for (const u of urls) {
    const rec = await fetchJson<CveRecord>(u);
    if (rec) return rec;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Record -> normalized summary.
// ---------------------------------------------------------------------------

function parseSeverity(
  s: string | undefined,
): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "high"; // default conservative-but-actionable
}

function englishDescription(descs: CveDescription[] | undefined): string {
  if (!Array.isArray(descs) || descs.length === 0) return "";
  const en = descs.find((d) => (d.lang || "").toLowerCase().startsWith("en"));
  return (en?.value || descs[0].value || "").trim();
}

function cwesFromRecord(cna: NonNullable<CveRecord["containers"]>["cna"]): string[] {
  const out = new Set<string>();
  for (const pt of cna?.problemTypes ?? []) {
    for (const d of pt.descriptions ?? []) {
      if (d.cweId && /^CWE-\d+$/.test(d.cweId)) out.add(d.cweId);
    }
  }
  return [...out];
}

function affectedStrings(cna: NonNullable<CveRecord["containers"]>["cna"]): string[] {
  const out: string[] = [];
  for (const a of cna?.affected ?? []) {
    if (a.packageName) out.push(a.packageName);
    if (a.vendor || a.product)
      out.push(`${a.vendor ?? ""}:${a.product ?? ""}`.replace(/^:|:$/g, ""));
    for (const cpe of a.cpes ?? []) out.push(cpe);
  }
  return out.filter((s) => s.trim().length > 0);
}

// Does any affected string match the AI package allowlist?
function packageAllowlistHit(affected: string[]): string | null {
  for (const raw of affected) {
    const s = raw.toLowerCase();
    if (MCP_TOKEN_RX.test(raw)) return "mcp";
    for (const tok of AI_PACKAGE_TOKENS) {
      const t = tok.toLowerCase();
      // bounded: token surrounded by separators or string edges
      const rx = new RegExp(
        `(?:^|[-_/@.\\s:])${t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:[-_/@.\\s:]|$)`,
        "i",
      );
      if (rx.test(s)) return tok;
    }
  }
  return null;
}

function severityFromMetrics(cna: NonNullable<CveRecord["containers"]>["cna"]): string | undefined {
  // CVE 5.x stores CVSS under containers.cna.metrics[].cvssV3_1/cvssV4_0 etc.
  // We only read baseSeverity when present; otherwise leave undefined.
  const metrics = (cna as unknown as { metrics?: unknown[] })?.metrics;
  if (!Array.isArray(metrics)) return undefined;
  for (const m of metrics) {
    if (!m || typeof m !== "object") continue;
    for (const v of Object.values(m as Record<string, unknown>)) {
      if (v && typeof v === "object" && "baseSeverity" in (v as object)) {
        const bs = (v as { baseSeverity?: string }).baseSeverity;
        if (bs) return bs;
      }
    }
  }
  return undefined;
}

function recordToSummary(rec: CveRecord): CveSummary | { error: string } {
  const meta = rec.cveMetadata;
  const cna = rec.containers?.cna;
  if (!meta?.cveId) return { error: "no cveMetadata.cveId" };
  if (!cna) return { error: `${meta.cveId}: no containers.cna` };
  if (meta.state && meta.state.toUpperCase() === "REJECTED")
    return { error: `${meta.cveId}: state=REJECTED` };

  const description = englishDescription(cna.descriptions);
  const title = (cna.title || "").trim();
  const cwes = cwesFromRecord(cna);
  const affected = affectedStrings(cna);
  const references = (cna.references ?? [])
    .map((r) => r.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);

  return {
    cve_id: meta.cveId,
    assigner: meta.assignerShortName || "unknown",
    title: title || description.slice(0, 120),
    description,
    cwes,
    severity: parseSeverity(severityFromMetrics(cna)),
    affected_strings: affected,
    references,
    published_at: meta.datePublished || null,
    admit_path: "ai-cna", // overwritten by caller
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE ids across rules/ + proposals/.
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

function buildKnownIndex(): Set<string> {
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
      const refs = (doc as { references?: { cve?: string[] } })?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      // Also pick up CVE ids from the filename (proposals named CVE-*.yaml).
      const m = f.match(/CVE-\d{4}-\d+/i);
      if (m) cves.add(m[0].toUpperCase());
    }
  }
  return cves;
}

// ---------------------------------------------------------------------------
// detection-readiness triage (same heuristics as sync-ghsa.ts).
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
    "<script>",
    "prompt: ['\"]",
    "\\$\\{",
    "\\beval\\(",
  ].join("|"),
  "im",
);

function isDetectionReady(s: CveSummary): { ready: boolean; reason: string } {
  const body = `${s.title}\n${s.description}`;
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return { ready: true, reason: "payload-like content in advisory body" };
  if (s.references.some((r) => /poc|exploit-db|github\.com\/.+\/(issues|commit|pull)/i.test(r)))
    return { ready: true, reason: "PoC / patch reference link present" };
  return {
    ready: false,
    reason: "advisory body has no reproducer / payload section",
  };
}

// ---------------------------------------------------------------------------
// YAML literal-block helper (ported from sync-ghsa.ts).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see references for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

// ---------------------------------------------------------------------------
// Proposal renderer (field-for-field aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------

function renderProposal(s: CveSummary): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const draftIdSuffix = s.cve_id.replace(/^CVE-/, "");
  const category = guessCategory(s.cwes);
  const triage = isDetectionReady(s);
  const relevance = agentRelevance({
    summary: s.title,
    description: s.description,
    cwes: s.cwes,
  });

  const responseActions =
    s.severity === "critical" || s.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = `  cve:\n    - "${s.cve_id}"\n`;
  const cweBlock =
    s.cwes.length > 0
      ? `  cwe:\n${s.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const externalRefs = s.references.length > 0 ? s.references : [s.cve_id ? `https://www.cve.org/CVERecord?id=${s.cve_id}` : ""];
  const externalBlock = `  external:\n${externalRefs
    .filter(Boolean)
    .map((u) => `    - "${u.replace(/"/g, '\\"')}"`)
    .join("\n")}\n`;

  const title = (s.title || s.cve_id).replace(/"/g, '\\"').slice(0, 120);
  const desc = (s.description || s.title || s.cve_id).replace(/\n+/g, " ").trim();
  const packageNote =
    s.affected_strings.length > 0 ? s.affected_strings.join(", ").slice(0, 300) : "unknown";

  // Advisory body / PoC commentary embedded under detection.conditions so the
  // human reviewer has the attack input ready to convert to regex.
  const bodyForComment = `${s.title}\n\n${s.description}`.trim();
  const advCommentLines = bodyForComment
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .slice(0, 60)
    .map((l) => `    # ${l}`)
    .join("\n");

  return `# ATR rule proposal -- generated by scripts/sync-cvelistv5.ts
# Source: MITRE CVE Program cvelistV5 (CNA firehose) -- ${s.cve_id}
# Assigner CNA: ${s.assigner}  |  admit path: ${s.admit_path}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The CNA advisory body
#         is attached as a YAML comment under detection.conditions and in
#         _cvelistv5_sync.advisory_body for conversion to a precision-safe
#         regex.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
# Agent relevance: ${relevance.reason}
title: "${title}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  MITRE cvelistV5 CNA disclosure ${s.cve_id} (assigner: ${s.assigner}).
  Affected: ${packageNote}.
  ${desc.slice(0, 600)}
author: "ATR Community (cvelistV5 sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${s.severity}

references:
${cveBlock}${cweBlock}${externalBlock}

metadata_provenance:
  cvelistv5: cvelistv5-sync
  cve: cvelistv5-sync
${s.cwes.length ? "  cwe: cvelistv5-sync\n" : ""}
tags:
  category: ${category}
  subcategory: cvelistv5-imported
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
    # TODO(human): convert the CNA advisory below into precision-safe
    # detection.conditions regex/string matchers. Without this work the
    # rule will neither fire nor be promotable to rules/.
    #
    # === CNA advisory excerpt (from cvelistV5 ${s.assigner}) ===
${advCommentLines || "    # (no advisory body in source record)"}
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

confidence: ${triage.ready ? 70 : 40}

test_cases:
  true_positives: []
  true_negatives: []

# === sync-cvelistv5.ts provenance ===
_cvelistv5_sync:
  cve_id: "${s.cve_id}"
  assigner_short_name: "${s.assigner}"
  admit_path: "${s.admit_path}"
  cwes: ${JSON.stringify(s.cwes)}
  affected: ${JSON.stringify(s.affected_strings.slice(0, 20))}
  severity: "${s.severity}"
  published_at: ${s.published_at ? `"${s.published_at}"` : "null"}
  references: ${JSON.stringify(s.references.slice(0, 20))}
  imported_at: "${new Date().toISOString()}"
  data_source_used: "cvelistV5 delta.json + raw record"
  advisory_body: |
${indentForLiteralBlock(bodyForComment || "(no body provided by CNA record)", "    ")}

# Triage flag read by promote-detection-ready.ts. Set true only when the CNA
# advisory body contains payload-like content (fenced code, PoC/exploit
# section, command/eval/payload strings); the generator lifts patterns from
# advisory_body, never from prose-only descriptions.
_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason}"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  mode: string;
  days_window: number;
  delta_new: number;
  delta_updated: number;
  records_fetched: number;
  fetch_failures: number;
  admitted_ai_cna: number;
  admitted_package: number;
  filtered_not_agent: number;
  filtered_out_of_window: number;
  filtered_no_admit_path: number;
  skipped_existing: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  errors: string[];
  written_files: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    mode: DAYS > 7 ? "backfill" : "daily",
    days_window: DAYS,
    delta_new: 0,
    delta_updated: 0,
    records_fetched: 0,
    fetch_failures: 0,
    admitted_ai_cna: 0,
    admitted_package: 0,
    filtered_not_agent: 0,
    filtered_out_of_window: 0,
    filtered_no_admit_path: 0,
    skipped_existing: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-cvelistv5.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"} | window: ${DAYS}d`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // --- pull delta feed ---
  const delta = await fetchJson<DeltaFeed>(DELTA_URL);
  if (!delta) {
    summary.errors.push(
      `delta.json unreachable at ${DELTA_URL} -- network or rate issue; daily cron will retry.`,
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::cvelistv5-summary::${JSON.stringify({
        new_proposals: 0,
        records_fetched: 0,
        fetch_failures: summary.fetch_failures,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  const newItems = Array.isArray(delta.new) ? delta.new : [];
  const updatedItems = Array.isArray(delta.updated) ? delta.updated : [];
  summary.delta_new = newItems.length;
  summary.delta_updated = updatedItems.length;
  console.error(
    `delta.json: ${newItems.length} new, ${updatedItems.length} updated (fetched ${delta.fetchTime ?? "?"})`,
  );

  // Daily mode reads new+updated; backfill (--days > 7) also reads
  // updated (already included). delta.json is a rolling snapshot; the --days
  // floor is applied per-record as a publish-date cutoff below.
  const sinceMs = Date.now() - DAYS * 86_400_000;
  const items: DeltaItem[] = [...newItems, ...updatedItems];

  // dedup delta items by cveId (a CVE can appear in both new+updated).
  const seenIds = new Set<string>();
  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const item of items) {
    if (writtenCount >= LIMIT) break;
    const cveId = (item.cveId || "").toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(cveId)) continue;
    if (seenIds.has(cveId)) continue;
    seenIds.add(cveId);

    // dedup against rules/ + proposals/ before paying for a record fetch.
    if (!FORCE && known.has(cveId)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have ${cveId}: already covered`);
      continue;
    }
    const outPath = join(PROPOSALS_DIR, `${cveId}.proposal.yaml`);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${cveId}`);
      continue;
    }

    let rec: CveRecord | null;
    try {
      rec = await fetchRecord(item);
    } catch (e) {
      summary.fetch_failures += 1;
      summary.errors.push(`fetch ${cveId}: ${(e as Error).message}`);
      continue;
    }
    if (!rec) {
      summary.fetch_failures += 1;
      if (VERBOSE) console.error(`  fetch-fail ${cveId}`);
      continue;
    }
    summary.records_fetched += 1;

    const parsed = recordToSummary(rec);
    if ("error" in parsed) {
      if (VERBOSE) console.error(`  parse-skip ${parsed.error}`);
      continue;
    }

    // --days publish-date floor (applies to both modes).
    if (parsed.published_at) {
      const pub = new Date(parsed.published_at).getTime();
      if (!Number.isNaN(pub) && pub < sinceMs) {
        summary.filtered_out_of_window += 1;
        if (VERBOSE) console.error(`  out-of-window ${cveId} (${parsed.published_at})`);
        continue;
      }
    }

    // --- admit path (a) AI CNA, OR (b) AI package allowlist ---
    const isAiCna = AI_CNA_SHORTNAMES.has(parsed.assigner.toLowerCase());
    const pkgHit = packageAllowlistHit(parsed.affected_strings);
    if (!isAiCna && !pkgHit) {
      summary.filtered_no_admit_path += 1;
      if (VERBOSE)
        console.error(
          `  no-admit-path ${cveId} (assigner=${parsed.assigner}, affected=${parsed.affected_strings.slice(0, 2).join("|") || "none"})`,
        );
      continue;
    }
    parsed.admit_path = isAiCna ? "ai-cna" : "package-allowlist";
    if (isAiCna) summary.admitted_ai_cna += 1;
    else summary.admitted_package += 1;

    // --- common gate: agent-runtime relevance (even for AI CNAs) ---
    const relevance = agentRelevance({
      summary: parsed.title,
      description: parsed.description,
      cwes: parsed.cwes,
    });
    if (!relevance.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(`  not-agent ${cveId}: ${relevance.reason}`);
      continue;
    }

    const triage = isDetectionReady(parsed);
    const body = renderProposal(parsed);
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${cveId}.proposal.yaml (${parsed.admit_path}, ${triage.ready ? "ready" : "tracking"})`);
    } else {
      console.error(`  would write ${cveId}.proposal.yaml (${parsed.admit_path}, ${triage.ready ? "ready" : "tracking"})`);
    }
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::cvelistv5-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      admitted_ai_cna: summary.admitted_ai_cna,
      admitted_package: summary.admitted_package,
      filtered_not_agent: summary.filtered_not_agent,
      filtered_no_admit_path: summary.filtered_no_admit_path,
      records_fetched: summary.records_fetched,
      skipped_existing: summary.skipped_existing,
      fetch_failures: summary.fetch_failures,
      data_source_used: "cvelistV5",
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
