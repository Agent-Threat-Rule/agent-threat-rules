#!/usr/bin/env npx tsx
/**
 * sync-msrc.ts
 *
 * Pulls Microsoft Security Response Center (MSRC) Security Update Guide
 * disclosures via the public CVRF v3.0 API and emits ATR rule proposals
 * under proposals/msrc/<CVE-id>.proposal.yaml.
 *
 * Why MSRC matters for ATR: Microsoft now issues CVEs for its AI/agent
 * products (Microsoft 365 Copilot, Copilot Studio, Azure AI Foundry,
 * Azure OpenAI, Semantic Kernel, Copilot Chat in Edge / VS Code). These
 * are first-party agent-runtime advisories — prompt injection, command
 * injection in a Copilot, M365 Copilot info-disclosure / RCE — exactly
 * ATR's scope. They also land in NVD eventually, so this source is mostly
 * about being EARLY and capturing the Microsoft-authored prose.
 *
 * Data source (public, no auth):
 *   - GET https://api.msrc.microsoft.com/cvrf/v3.0/updates
 *       Header Accept: application/json. Returns monthly update docs with
 *       IDs like "2026-Jun" (the "<Year> <Month> Security Updates" docs)
 *       plus assorted "Mariner Release Notes" docs we ignore.
 *   - GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<ID>
 *       Returns a CVRF doc: { ProductTree, Vulnerability[] }. Each
 *       Vulnerability has CVE, Title.Value, Notes[] (Type 2 = Description
 *       HTML prose; Type 4 = FAQ), ProductStatuses[] (ProductID refs into
 *       ProductTree.FullProductName), Threats[] (Type 0 = impact e.g.
 *       "Remote Code Execution"; Type 3 = severity "Critical"), and
 *       CVSSScoreSets[].
 *
 * CRITICAL FILTER — AI/agent products only:
 *   MSRC covers EVERY Microsoft product (700-1100+ CVEs/month: Windows,
 *   Office, Exchange, SQL Server, ...). We resolve each vulnerability's
 *   affected product names (ProductStatuses ProductID -> FullProductName
 *   Value) and keep ONLY entries whose product name matches an AI keyword
 *   (copilot / azure ai / ai foundry / semantic kernel / azure openai /
 *   prompt / copilot studio / azure machine learning). Everything else is
 *   dropped. In practice this is 3-8 CVEs/month out of ~700-1100.
 *
 * Second gate: the same agentRelevance() CWE/keyword check used by
 * sync-ghsa.ts. MSRC gives no structured CWE, so we infer CWEs from the
 * Description prose + the Threats impact label, then run agentRelevance.
 *
 * Detection readiness: MSRC advisories are PROSE (no PoC, no payloads).
 * _triage.detection_ready is therefore almost always false; it is set true
 * only if payload-like content (code fence, curl, explicit payload string)
 * appears in the body — which essentially never happens for MSRC.
 *
 * Dedup: CVE id is the cross-source primary key. We skip any CVE already
 * present in rules/ or proposals/ (buildKnownIndex), unless --force. These
 * CVEs also appear in NVD/GHSA, so dedup keeps only agent-relevant net-new.
 *
 * Crawl window: a daily run crawls only the most recent 1-2 monthly docs.
 * For backfill use --months N (default 3 here, the most-recent N months).
 *
 * Usage:
 *   npx tsx scripts/sync-msrc.ts                       # dry-run, last 3 months
 *   npx tsx scripts/sync-msrc.ts --months 2 --verbose  # last 2 months
 *   npx tsx scripts/sync-msrc.ts --write               # write proposals
 *   npx tsx scripts/sync-msrc.ts --force               # overwrite existing
 *   npx tsx scripts/sync-msrc.ts --limit 5             # cap output
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path available (recoverable — e.g. updates list unreachable)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "msrc");

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
const MONTHS = opt("--months") ? Math.max(1, parseInt(opt("--months")!, 10)) : 3;

const MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0";
const USER_AGENT =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// ---------------------------------------------------------------------------
// CRITICAL FILTER: AI/agent product-name keywords. A vulnerability is kept
// only if at least one affected product name matches one of these. Order is
// irrelevant; matching is lowercase substring.
// ---------------------------------------------------------------------------
const AI_PRODUCT_KEYWORDS = [
  "copilot",
  "azure ai",
  "ai foundry",
  "semantic kernel",
  "azure openai",
  "copilot studio",
  "azure machine learning",
  "prompt",
];

// ---------------------------------------------------------------------------
// CWE -> ATR category (subset shared with sync-ghsa.ts CWE_TO_CATEGORY).
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
};

function guessCategory(cwes: string[]): string {
  for (const c of cwes) {
    if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  }
  return "model-abuse";
}

// Agent-relevant CWEs (same set as sync-ghsa.ts) — content-layer agent
// threats ATR can write a detection for. Memory-safety / availability CWEs
// are deliberately excluded.
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
  /information disclosure/,
  /spoofing/,
  /elevation of privilege/,
  /security feature bypass/,
  /untrusted (input|data|manifest|model|content)/,
];

// Second gate (after the AI product filter): is this advisory an
// agent-runtime threat ATR could detect? Relevant if it carries an
// agent-relevant CWE OR an agent-threat keyword.
export function agentRelevance(adv: {
  summary?: string;
  description?: string;
  cwes?: Array<{ cwe_id: string }>;
}): { relevant: boolean; reason: string } {
  const cwes = (adv.cwes ?? []).map((c) => c.cwe_id);
  const hitCwe = cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const body = `${adv.summary ?? ""}\n${adv.description ?? ""}`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  return {
    relevant: false,
    reason: `no agent-relevant CWE or keyword (cwes: ${cwes.join(",") || "none"})`,
  };
}

// MSRC gives no structured CWE. Infer likely CWE(s) from the description
// prose + impact label so category mapping + agentRelevance have a signal.
function inferCwes(text: string): string[] {
  const t = text.toLowerCase();
  const out: string[] = [];
  const add = (c: string) => {
    if (!out.includes(c)) out.push(c);
  };
  if (/os command|command injection|command \('?command injection/.test(t))
    add("CWE-78");
  if (/\bcode injection\b/.test(t)) add("CWE-94");
  if (/remote code execution|arbitrary code|execute code/.test(t)) add("CWE-94");
  if (/eval injection/.test(t)) add("CWE-95");
  if (/deserializ/.test(t)) add("CWE-502");
  if (/server-side request|\bssrf\b/.test(t)) add("CWE-918");
  if (/path traversal|directory traversal/.test(t)) add("CWE-22");
  if (/sql injection/.test(t)) add("CWE-89");
  if (/cross-site scripting|\bxss\b/.test(t)) add("CWE-79");
  if (/template injection/.test(t)) add("CWE-1336");
  if (/prompt injection/.test(t)) add("CWE-1336");
  if (/information disclosure|sensitive information|exfiltrat/.test(t))
    add("CWE-200");
  if (/elevation of privilege|privilege escalation/.test(t)) add("CWE-863");
  if (/spoofing/.test(t)) add("CWE-20");
  if (/improper neutralization|special elements/.test(t)) add("CWE-74");
  return out;
}

// ---------------------------------------------------------------------------
// MSRC CVRF API types (only the fields we use).
// ---------------------------------------------------------------------------
interface MsrcUpdateEntry {
  ID: string;
  Alias?: string;
  DocumentTitle: string;
  Severity?: string | null;
  InitialReleaseDate?: string;
  CurrentReleaseDate?: string;
  CvrfUrl?: string;
}
interface MsrcUpdatesResponse {
  value: MsrcUpdateEntry[];
}
interface MsrcNote {
  Title?: string;
  Type?: number;
  Ordinal?: string;
  Value?: string | null;
}
interface MsrcThreat {
  Description?: { Value?: string };
  ProductID?: string[];
  Type?: number;
}
interface MsrcCvss {
  BaseScore?: number;
  Vector?: string;
  ProductID?: string[];
}
interface MsrcProductStatus {
  ProductID?: string[];
  Type?: number;
}
interface MsrcVulnerability {
  Title?: { Value?: string };
  Notes?: MsrcNote[];
  CVE?: string;
  ProductStatuses?: MsrcProductStatus[];
  Threats?: MsrcThreat[];
  CVSSScoreSets?: MsrcCvss[];
}
interface MsrcFullProduct {
  ProductID: string;
  CPE?: string;
  Value: string;
}
interface MsrcCvrfDoc {
  DocumentTitle?: { Value?: string } | string;
  ProductTree?: { FullProductName?: MsrcFullProduct[] };
  Vulnerability?: MsrcVulnerability[];
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { Accept: "application/json", "User-Agent": USER_AGENT },
  });
  if (!res.ok) {
    throw new Error(`MSRC fetch failed: ${res.status} ${res.statusText} (${url})`);
  }
  return (await res.json()) as T;
}

// Pick the most recent N "<Year> <Month> Security Updates" docs. Skip the
// "Mariner Release Notes" and any non-monthly doc. IDs look like "2026-Jun".
const MONTHLY_ID_RX = /^\d{4}-[A-Z][a-z]{2}$/;
function selectRecentMonths(
  updates: MsrcUpdateEntry[],
  n: number,
): MsrcUpdateEntry[] {
  const monthly = updates.filter(
    (u) =>
      MONTHLY_ID_RX.test(u.ID) &&
      /security updates/i.test(u.DocumentTitle || ""),
  );
  monthly.sort((a, b) =>
    (b.InitialReleaseDate || "").localeCompare(a.InitialReleaseDate || ""),
  );
  return monthly.slice(0, n);
}

// ---------------------------------------------------------------------------
// Normalize one MSRC vulnerability into a flat advisory shape.
// ---------------------------------------------------------------------------
interface NormalizedAdvisory {
  cve: string;
  title: string;
  description: string; // plain text (HTML stripped)
  affectedProducts: string[];
  matchedProducts: string[]; // products that matched the AI keyword filter
  severity: "critical" | "high" | "medium" | "low";
  cwes: string[];
  impact: string | null; // Threats Type 0 e.g. "Remote Code Execution"
  cvssScore: number | null;
  cvssVector: string | null;
  msrcUrl: string;
}

function stripHtml(s: string): string {
  return s
    .replace(/<\/(p|div|li|br|h\d)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]+\n/g, "\n")
    .trim();
}

function severityFromThreats(
  v: MsrcVulnerability,
  cvss: number | null,
): "critical" | "high" | "medium" | "low" {
  for (const t of v.Threats ?? []) {
    if (t.Type === 3 && t.Description?.Value) {
      const s = t.Description.Value.toLowerCase();
      if (s.includes("critical")) return "critical";
      if (s.includes("important") || s.includes("high")) return "high";
      if (s.includes("moderate") || s.includes("medium")) return "medium";
      if (s.includes("low")) return "low";
    }
  }
  // Fall back to CVSS base score buckets.
  if (cvss !== null) {
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    return "low";
  }
  return "high";
}

function descriptionOf(v: MsrcVulnerability): string {
  for (const n of v.Notes ?? []) {
    if (n.Type === 2 && typeof n.Value === "string" && n.Value.trim()) {
      return stripHtml(n.Value);
    }
  }
  return "";
}

function impactOf(v: MsrcVulnerability): string | null {
  for (const t of v.Threats ?? []) {
    if (t.Type === 0 && t.Description?.Value) return t.Description.Value;
  }
  return null;
}

function normalize(
  v: MsrcVulnerability,
  id2name: Map<string, string>,
): NormalizedAdvisory | null {
  const cve = (v.CVE || "").trim();
  if (!/^CVE-\d{4}-\d+$/.test(cve)) return null;

  const affected = new Set<string>();
  for (const ps of v.ProductStatuses ?? []) {
    for (const pid of ps.ProductID ?? []) {
      const nm = id2name.get(pid);
      if (nm) affected.add(nm);
    }
  }
  const affectedProducts = [...affected];
  const matched = affectedProducts.filter((n) =>
    AI_PRODUCT_KEYWORDS.some((k) => n.toLowerCase().includes(k)),
  );
  // CRITICAL FILTER: drop everything that does not touch an AI product.
  if (matched.length === 0) return null;

  const title = (v.Title?.Value || cve).trim();
  const description = descriptionOf(v);
  const impact = impactOf(v);

  // CVSS: pick the highest base score across score sets.
  let cvssScore: number | null = null;
  let cvssVector: string | null = null;
  for (const c of v.CVSSScoreSets ?? []) {
    if (typeof c.BaseScore === "number") {
      if (cvssScore === null || c.BaseScore > cvssScore) {
        cvssScore = c.BaseScore;
        cvssVector = c.Vector || null;
      }
    }
  }

  const severity = severityFromThreats(v, cvssScore);
  const cwes = inferCwes(`${title}\n${description}\n${impact ?? ""}`);

  return {
    cve,
    title,
    description,
    affectedProducts,
    matchedProducts: matched,
    severity,
    cwes,
    impact,
    cvssScore,
    cvssVector,
    msrcUrl: `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`,
  };
}

// ---------------------------------------------------------------------------
// Detection readiness — MSRC is prose-only, so almost always false.
// ---------------------------------------------------------------------------
const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "payload:",
    "curl ",
    "POST \\/[a-z]",
    "<script>",
    "GET \\/[a-z].*HTTP",
    "\\$\\{.*\\}",
  ].join("|"),
  "im",
);

function isDetectionReady(adv: NormalizedAdvisory): {
  ready: boolean;
  reason: string;
} {
  const body = `${adv.title}\n${adv.description}`;
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return { ready: true, reason: "payload-like content in advisory body" };
  return {
    ready: false,
    reason:
      "MSRC advisory is prose-only (no PoC / payload) — tracking until a " +
      "reviewer adds detection conditions",
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE ids across rules/ and proposals/.
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
        if (typeof v === "string") cves.add(v);
        else if (Array.isArray(v))
          for (const c of v) if (typeof c === "string") cves.add(c);
      }
    }
  }
  return { cves };
}

// ---------------------------------------------------------------------------
// Proposal renderer (column-for-column aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------
const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see MSRC url for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(adv: NormalizedAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const category = guessCategory(adv.cwes);
  const triage = isDetectionReady(adv);
  const responseActions =
    adv.severity === "critical" || adv.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = `  cve:\n    - "${adv.cve}"\n`;
  const cweBlock =
    adv.cwes.length > 0
      ? `  cwe:\n${adv.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";

  const title = adv.title.replace(/"/g, '\\"').slice(0, 120);
  const descOneLine = (adv.description || adv.title)
    .replace(/\n+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 600);
  const productNote = adv.matchedProducts.join(", ");

  // advisory_body: full Title + Description prose — this is the ONLY payload
  // source for a future promote-detection-ready.ts pass.
  const advisoryBody = `${adv.title}\n\n${adv.description || "(no description provided by MSRC)"}`;

  return `# ATR rule proposal -- generated by scripts/sync-msrc.ts
# Source: Microsoft MSRC Security Update Guide (CVRF v3.0) ${adv.cve}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. MSRC advisories are
#         prose (no PoC), so detection_ready is almost always false; the full
#         advisory body is attached under _msrc_sync.advisory_body for a human
#         to convert into precision-safe conditions.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${adv.cve}
rule_version: 1
status: draft
description: >
  Microsoft MSRC advisory ${adv.cve} affecting ${productNote}.
  ${descOneLine}
author: "ATR Community (MSRC sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${adv.severity}

references:
${cveBlock}${cweBlock}  external:
    - "${adv.msrcUrl}"

metadata_provenance:
  msrc: msrc-sync
  cve: msrc-sync
${adv.cwes.length ? "  cwe: msrc-sync\n" : ""}
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
    # TODO(human): convert the MSRC advisory body below into precision-safe
    # detection.conditions. MSRC publishes prose (no payload), so this usually
    # needs reviewer-supplied attack input before it can fire or be promoted.
    #
    # === MSRC advisory (Title + Description) ===
${advisoryBody
  .split("\n")
  .slice(0, 60)
  .map((s) => `    # ${s}`)
  .join("\n")}
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

# === sync-msrc.ts provenance ===
_msrc_sync:
  cve: "${adv.cve}"
  matched_products: ${JSON.stringify(adv.matchedProducts)}
  affected_products: ${JSON.stringify(adv.affectedProducts)}
  impact: ${adv.impact ? `"${adv.impact.replace(/"/g, '\\"')}"` : "null"}
  severity: "${adv.severity}"
  cvss_score: ${adv.cvssScore ?? "null"}
  cvss_vector: ${adv.cvssVector ? `"${adv.cvssVector.replace(/"/g, '\\"')}"` : "null"}
  inferred_cwes: ${JSON.stringify(adv.cwes)}
  msrc_url: "${adv.msrcUrl}"
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
  months_crawled: string[];
  vulnerabilities_scanned: number;
  ai_product_matched: number;
  filtered_not_agent: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  errors: string[];
  written_files: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    months_crawled: [],
    vulnerabilities_scanned: 0,
    ai_product_matched: 0,
    filtered_not_agent: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-msrc.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"} | months: ${MONTHS}`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // 1. List monthly update docs.
  let updates: MsrcUpdatesResponse;
  try {
    updates = await fetchJson<MsrcUpdatesResponse>(`${MSRC_BASE}/updates`);
  } catch (e) {
    summary.errors.push(`updates list unreachable: ${(e as Error).message}`);
    console.error(`fatal-recoverable: ${(e as Error).message}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(`::msrc-summary::${JSON.stringify({ new_proposals: 0 })}`);
    process.exit(2);
  }
  if (!Array.isArray(updates.value) || updates.value.length === 0) {
    summary.errors.push("updates list empty or wrong shape");
    console.log(JSON.stringify(summary, null, 2));
    console.log(`::msrc-summary::${JSON.stringify({ new_proposals: 0 })}`);
    process.exit(2);
  }

  const months = selectRecentMonths(updates.value, MONTHS);
  if (months.length === 0) {
    summary.errors.push("no monthly 'Security Updates' docs found");
    console.log(JSON.stringify(summary, null, 2));
    console.log(`::msrc-summary::${JSON.stringify({ new_proposals: 0 })}`);
    process.exit(2);
  }
  console.error(`crawling months: ${months.map((m) => m.ID).join(", ")}`);

  const known = buildKnownIndex();
  let writtenCount = 0;
  const seenCves = new Set<string>();

  for (const m of months) {
    if (writtenCount >= LIMIT) break;
    summary.months_crawled.push(m.ID);
    let doc: MsrcCvrfDoc;
    try {
      doc = await fetchJson<MsrcCvrfDoc>(`${MSRC_BASE}/cvrf/${m.ID}`);
    } catch (e) {
      summary.errors.push(`cvrf ${m.ID}: ${(e as Error).message}`);
      console.error(`  skip month ${m.ID}: ${(e as Error).message}`);
      continue;
    }

    const id2name = new Map<string, string>();
    for (const fp of doc.ProductTree?.FullProductName ?? []) {
      if (fp.ProductID && fp.Value) id2name.set(fp.ProductID, fp.Value);
    }

    const vulns = doc.Vulnerability ?? [];
    if (VERBOSE) console.error(`  ${m.ID}: ${vulns.length} vulnerabilities`);

    for (const v of vulns) {
      if (writtenCount >= LIMIT) break;
      summary.vulnerabilities_scanned += 1;

      // CRITICAL FILTER applied inside normalize() (AI product keyword).
      const adv = normalize(v, id2name);
      if (!adv) continue;
      summary.ai_product_matched += 1;

      // Second gate: agent-runtime relevance.
      const relevance = agentRelevance({
        summary: adv.title,
        description: `${adv.description} ${adv.impact ?? ""}`,
        cwes: adv.cwes.map((c) => ({ cwe_id: c })),
      });
      if (!relevance.relevant) {
        summary.filtered_not_agent += 1;
        if (VERBOSE)
          console.error(
            `  skip (not agent) ${adv.cve}: ${relevance.reason} [${adv.matchedProducts.join(",")}]`,
          );
        continue;
      }

      if (seenCves.has(adv.cve)) continue;
      seenCves.add(adv.cve);

      if (!FORCE && known.cves.has(adv.cve)) {
        summary.already_known += 1;
        if (VERBOSE) console.error(`  have ${adv.cve}: already covered`);
        continue;
      }
      const outPath = join(PROPOSALS_DIR, `${adv.cve}.proposal.yaml`);
      if (existsSync(outPath) && !FORCE) {
        summary.already_known += 1;
        if (VERBOSE) console.error(`  have-proposal ${adv.cve}`);
        continue;
      }

      const triage = isDetectionReady(adv);
      const body = renderProposal(adv);
      summary.new_proposals += 1;
      if (triage.ready) summary.new_detection_ready += 1;
      else summary.new_tracking_only += 1;

      if (WRITE) {
        writeFileSync(outPath, body, "utf-8");
        summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
        console.error(
          `  wrote ${adv.cve}.proposal.yaml [${adv.matchedProducts.join(",")}]`,
        );
      } else {
        console.error(
          `  would write ${adv.cve}.proposal.yaml [${adv.matchedProducts.join(",")}] sev=${adv.severity} cwes=${adv.cwes.join(",") || "none"}`,
        );
      }
      writtenCount += 1;
    }
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::msrc-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      ai_product_matched: summary.ai_product_matched,
      filtered_not_agent: summary.filtered_not_agent,
      already_known: summary.already_known,
      vulnerabilities_scanned: summary.vulnerabilities_scanned,
      months_crawled: summary.months_crawled,
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
