#!/usr/bin/env npx tsx
/**
 * sync-cisco-psirt.ts
 *
 * Pulls Cisco PSIRT advisories from the Cisco openVuln API and emits ATR rule
 * proposals under proposals/cisco-psirt/<CVE-or-advisory-id>.proposal.yaml.
 *
 * WHY CISCO PSIRT MATTERS FOR ATR
 *   Cisco ships a growing line of agent / GenAI products — Cisco AI Defense,
 *   Cisco AI Assistant (across Security Cloud / Webex / Meraki), and the
 *   Hypershield / AI runtime stack. When those products carry an agent-runtime
 *   vulnerability (prompt injection, tool/MCP poisoning, context exfiltration,
 *   excessive autonomy), the canonical machine-readable disclosure is the Cisco
 *   openVuln API (CSAF / CVRF + REST JSON). Cisco is also a likely upstream /
 *   partner relationship (Cisco AI Defense + skill-scanner), so tracking their
 *   agent-relevant CVEs keeps ATR aligned with their disclosures.
 *
 * DATA SOURCE — Cisco openVuln API (https://developer.cisco.com/docs/psirt/)
 *   Auth: OAuth2 client-credentials grant (free registration on the Cisco API
 *   Console / apiconsole.cisco.com → register an app for "Cisco PSIRT openVuln
 *   API"). Two secrets:
 *       CISCO_PSIRT_CLIENT_ID
 *       CISCO_PSIRT_CLIENT_SECRET
 *   Token endpoint (Cisco moved auth to Okta-backed id.cisco.com):
 *       POST https://id.cisco.com/oauth2/default/v1/token
 *            grant_type=client_credentials
 *            client_id / client_secret  (form-encoded, per OAuth2)
 *       -> { access_token, token_type: "Bearer", expires_in }
 *   Advisory endpoints (v2, JSON):
 *       GET https://apix.cisco.com/security/advisories/v2/all
 *       GET https://apix.cisco.com/security/advisories/v2/product?product=...
 *       GET https://apix.cisco.com/security/advisories/v2/cve/{CVE-id}
 *   Each advisory record (the "advisories" array) carries: advisoryId,
 *   advisoryTitle, sir (Security Impact Rating), cves[], cwe[], summary
 *   (HTML), firstPublished, lastUpdated, publicationUrl, cvssBaseScore,
 *   bugIDs, productNames[].
 *
 * SCOPE DISCIPLINE (mirrors sync-aws-psirt.ts / sync-ghsa.ts — DO NOT widen)
 *   ATR detects AGENT-runtime threats. The /all firehose returns Cisco's
 *   ENTIRE advisory corpus (IOS XE, ASA, firewalls, etc.) — almost none of it
 *   agent-relevant. Two gates, BOTH must pass:
 *     Gate 1 (Cisco AI/agent product keyword): the title + summary + product
 *            names must mention an AI/agent surface (AI Defense, AI Assistant,
 *            Hypershield AI, MCP, "AI agent", GenAI, ...).
 *     Gate 2 (shared agentRelevance() from sync-ghsa.ts): an agent-relevant CWE
 *            OR an agent-threat keyword in the body.
 *   This keeps the bulk Cisco networking-gear CVEs out of ATR.
 *
 * DEDUP
 *   CVE id is the cross-source primary key. buildKnownIndex() scans rules/ and
 *   proposals/ for references.cve (and the Cisco advisory id). Same CVE / same
 *   advisory id already present -> skip unless --force.
 *
 * DETECTION READINESS
 *   Cisco advisory summaries are prose (impact + fixed-release tables), almost
 *   never a reproducer. detection_ready is therefore usually false. The full
 *   de-HTML'd summary goes into `_cisco_psirt_sync.advisory_body` — the single
 *   payload source the downstream promote-detection-ready.ts crystalliser reads.
 *
 * SECRET DISCIPLINE (hard rule — see ~/CLAUDE.md secret discipline)
 *   CISCO_PSIRT_CLIENT_ID and CISCO_PSIRT_CLIENT_SECRET are read ONLY from
 *   process.env. There is NO --id / --secret CLI flag. They are never echoed,
 *   never logged, never placed on argv. Missing either => a clear message +
 *   exit 2 (recoverable, NOT fatal). In an environment with no Cisco creds
 *   (the default) this is the EXPECTED, clean outcome.
 *
 * Usage:
 *   npx tsx scripts/sync-cisco-psirt.ts                 # dry-run
 *   npx tsx scripts/sync-cisco-psirt.ts --write         # write proposals
 *   npx tsx scripts/sync-cisco-psirt.ts --force         # overwrite existing
 *   npx tsx scripts/sync-cisco-psirt.ts --verbose
 *   npx tsx scripts/sync-cisco-psirt.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error, schema mismatch)
 *   2 no data path (recoverable — e.g. CISCO_PSIRT_CLIENT_ID/SECRET not set,
 *     OAuth/auth failure, or rate limit; daily cron retries)
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

// Reuse the battle-tested agent-relevance gate from sync-ghsa (single source of
// truth for what counts as an agent-runtime threat).
import { agentRelevance } from "./sync-ghsa.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "cisco-psirt");

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
// Secret discipline: OAuth2 client-credentials from env ONLY. No --id/--secret
// flag. Never echoed. (Read here only so main() can detect "missing" early.)
// ---------------------------------------------------------------------------
const CISCO_PSIRT_CLIENT_ID = process.env.CISCO_PSIRT_CLIENT_ID;
const CISCO_PSIRT_CLIENT_SECRET = process.env.CISCO_PSIRT_CLIENT_SECRET;

// Cisco openVuln endpoints (verified against developer.cisco.com/docs/psirt/).
const TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token";
const API_BASE = "https://apix.cisco.com/security/advisories/v2";
const ADVISORIES_ALL_URL = `${API_BASE}/all`;

const FETCH_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "ATR-Sync/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// openVuln rate limits are generous (per-second / per-day app limits). We make
// at most a couple of calls (token + /all), so no paging loop is needed, but we
// keep a polite inter-call pause for any future multi-call path.
const CALL_DELAY_MS = 250;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Gate 1: Cisco AI / agent product keyword set. Tokens chosen to specifically
// indicate an AGENT / GenAI surface, NOT generic Cisco networking gear. Cisco
// AI Defense, Cisco AI Assistant, AgentCore/agent runtime, Hypershield AI, MCP
// are the strongest agent signals.
// ---------------------------------------------------------------------------
const CISCO_AI_PRODUCT_RX: RegExp[] = [
  /\bai defense\b/i, // Cisco AI Defense
  /\bai assistant\b/i, // Cisco AI Assistant (Security Cloud / Webex / Meraki)
  /\bai[- ]agent\b/i,
  /\bagentic\b/i,
  /\bhypershield\b/i, // Cisco Hypershield (AI-native runtime security)
  /model context protocol/i,
  /\bmcp\b/i,
  /\bgenai\b/i,
  /generative ai/i,
  /\bllm\b/i,
  /large language model/i,
  /prompt injection/i,
  /\bcopilot\b/i,
  /\bwebex ai\b/i,
];

function ciscoAiProductHit(text: string): string | null {
  for (const rx of CISCO_AI_PRODUCT_RX) {
    if (rx.test(text)) return rx.source;
  }
  return null;
}

// ---------------------------------------------------------------------------
// CWE → ATR category map (mirrors sync-ghsa.ts CWE_TO_CATEGORY exactly).
// Fallback per contract: "model-abuse".
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

function guessCategory(cwes: string[], body: string): string {
  for (const c of cwes) if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  // Text fallback when the Cisco advisory carries no mapped CWE.
  const h = body.toLowerCase();
  if (/prompt[- ]injection|jailbreak/.test(h)) return "prompt-injection";
  if (/tool (execution|invocation|call)|without (authorization|confirmation)|excessive|autonom/.test(h))
    return "excessive-agency";
  if (/\bmcp\b|tool poisoning|command injection|\brce\b|remote code execution|arbitrary code|sandbox/.test(h))
    return "tool-poisoning";
  if (/ssrf|server[- ]side request|path traversal|file (access|read)|exfiltrat|information disclosure/.test(h))
    return "context-exfiltration";
  if (/authoriz|authentic|privilege/.test(h)) return "privilege-escalation";
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// OAuth2 client-credentials token fetch. Secrets used here only; never logged.
// Returns the access token string, or throws/exits on failure.
// ---------------------------------------------------------------------------
async function fetchAccessToken(): Promise<string | null> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
      // client_id / client_secret in the body per OAuth2 client-credentials.
      // (Cisco's Okta token endpoint also accepts HTTP Basic; body form is the
      // documented openVuln path.) Secrets never go on argv or into logs.
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: CISCO_PSIRT_CLIENT_ID!,
        client_secret: CISCO_PSIRT_CLIENT_SECRET!,
      }).toString(),
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(t);
    // Network / timeout reaching the token endpoint — recoverable.
    console.error(
      `Cisco OAuth token request failed (network/timeout): ${(e as Error).message}`,
    );
    return null;
  }
  clearTimeout(t);

  if (res.status === 400 || res.status === 401 || res.status === 403) {
    // Bad / unauthorized credentials. Recoverable: user must fix the creds.
    // We deliberately do NOT print the response body (it can echo the request).
    console.error(
      `Cisco OAuth auth failed (${res.status}). CISCO_PSIRT_CLIENT_ID / ` +
        "CISCO_PSIRT_CLIENT_SECRET are missing or invalid. Register a free app " +
        "for the Cisco PSIRT openVuln API at apiconsole.cisco.com and set both " +
        "env vars.",
    );
    return null;
  }
  if (!res.ok) {
    console.error(
      `Cisco OAuth token endpoint returned ${res.status} ${res.statusText}.`,
    );
    return null;
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch {
    console.error("Cisco OAuth token response was not valid JSON.");
    return null;
  }
  const token = (json as { access_token?: unknown })?.access_token;
  if (typeof token !== "string" || token.length === 0) {
    console.error("Cisco OAuth token response had no access_token field.");
    return null;
  }
  return token;
}

// ---------------------------------------------------------------------------
// openVuln advisory record + fetch.
// ---------------------------------------------------------------------------
interface CiscoAdvisoryRaw {
  advisoryId?: string;
  advisoryTitle?: string;
  sir?: string; // Security Impact Rating: Critical/High/Medium/Low
  firstPublished?: string;
  lastUpdated?: string;
  cves?: string[] | string;
  cwe?: string[] | string;
  bugIDs?: string[] | string;
  cvssBaseScore?: string | number;
  publicationUrl?: string;
  summary?: string; // HTML
  productNames?: string[] | string;
}

interface CiscoAdvisoriesEnvelope {
  advisories?: CiscoAdvisoryRaw[];
}

async function fetchAllAdvisories(
  token: string,
): Promise<CiscoAdvisoryRaw[] | null> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(ADVISORIES_ALL_URL, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(t);
    console.error(`Cisco advisories fetch failed: ${(e as Error).message}`);
    return null;
  }
  clearTimeout(t);

  if (res.status === 401 || res.status === 403) {
    console.error(
      `Cisco advisories endpoint returned ${res.status} (token rejected/expired).`,
    );
    return null;
  }
  if (res.status === 429) {
    console.error(
      "Cisco openVuln rate limit hit (429). The daily cron will retry.",
    );
    return null;
  }
  if (res.status === 404) {
    // /all with no matching advisories returns 404 in openVuln — treat as empty.
    if (VERBOSE) console.error("Cisco /all returned 404 (no advisories).");
    return [];
  }
  if (!res.ok) {
    throw new Error(
      `Cisco advisories /all failed: ${res.status} ${res.statusText}`,
    );
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch {
    throw new Error("Cisco advisories /all returned non-JSON body.");
  }
  const env = json as CiscoAdvisoriesEnvelope;
  if (!env || !Array.isArray(env.advisories)) {
    throw new Error(
      "Cisco advisories /all envelope missing advisories[] — API schema may have changed.",
    );
  }
  return env.advisories;
}

// ---------------------------------------------------------------------------
// Normalisation helpers.
// ---------------------------------------------------------------------------
function asStringArray(v: string[] | string | undefined): string[] {
  if (Array.isArray(v))
    return v.filter((s): s is string => typeof s === "string" && s.length > 0);
  if (typeof v === "string" && v.length > 0) return [v];
  return [];
}

function extractCves(parts: string[]): string[] {
  const set = new Set<string>();
  const rx = /CVE-\d{4}-\d{4,7}/gi;
  for (const p of parts) {
    let m: RegExpExecArray | null;
    while ((m = rx.exec(p))) set.add(m[0].toUpperCase());
  }
  return [...set];
}

function normalizeCwes(parts: string[]): string[] {
  const set = new Set<string>();
  const rx = /CWE-\d{1,5}/gi;
  for (const p of parts) {
    let m: RegExpExecArray | null;
    while ((m = rx.exec(p))) set.add(m[0].toUpperCase());
  }
  return [...set];
}

// Cisco SIR (Security Impact Rating) -> ATR severity.
function severityFromSir(sir: string | undefined): "critical" | "high" | "medium" | "low" {
  const v = (sir || "").toLowerCase();
  if (v.startsWith("crit")) return "critical";
  if (v === "high") return "high";
  if (v === "medium" || v === "moderate") return "medium";
  if (v === "low") return "low";
  return "high"; // PSIRT advisories without SIR — bias up.
}

function htmlToText(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

interface CiscoAdvisory {
  advisory_id: string;
  title: string;
  body: string; // de-HTML'd plain text
  cve_ids: string[];
  cwe_ids: string[];
  bug_ids: string[];
  severity: "critical" | "high" | "medium" | "low";
  cvss_base_score: string | null;
  publication_url: string | null;
  first_published: string | null;
  last_updated: string | null;
  product_names: string[];
}

function normalizeAdvisory(raw: CiscoAdvisoryRaw): CiscoAdvisory | null {
  const advisoryId = (raw.advisoryId || "").toString().trim();
  const title = (raw.advisoryTitle || "").toString().trim();
  if (!advisoryId && !title) return null;
  const body = htmlToText((raw.summary || "").toString());
  const products = asStringArray(raw.productNames);
  const searchText = `${title}\n${body}\n${products.join("\n")}`;
  return {
    advisory_id: advisoryId || title.slice(0, 40),
    title,
    body,
    cve_ids: extractCves([...asStringArray(raw.cves), title, body]),
    cwe_ids: normalizeCwes([...asStringArray(raw.cwe), body]),
    bug_ids: asStringArray(raw.bugIDs),
    severity: severityFromSir(raw.sir),
    cvss_base_score:
      raw.cvssBaseScore != null ? String(raw.cvssBaseScore) : null,
    publication_url: (raw.publicationUrl || "").toString() || null,
    first_published: (raw.firstPublished || "").toString() || null,
    last_updated: (raw.lastUpdated || "").toString() || null,
    product_names: products,
  };
}

// ---------------------------------------------------------------------------
// Detection readiness — Cisco advisories are prose; usually false.
// ---------------------------------------------------------------------------
const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "Proof of Concept",
    "Reproducer",
    "payload:",
    "curl ",
    "POST /",
    "GET /",
    "<script>",
    "\\$\\{",
  ].join("|"),
  "im",
);

function isDetectionReady(a: CiscoAdvisory): { ready: boolean; reason: string } {
  if (PAYLOAD_HEURISTICS_RX.test(a.body))
    return { ready: true, reason: "payload-like content in advisory summary" };
  return {
    ready: false,
    reason: "Cisco advisory is prose-only (impact + fixed-release tables, no PoC)",
  };
}

// ---------------------------------------------------------------------------
// Idempotency index across rules/ and proposals/ — CVE ids + Cisco advisory ids.
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
  ciscoIds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const ciscoIds = new Set<string>();
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
          references?: { cve?: string[]; cisco_advisory?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
      if (refs?.cisco_advisory) {
        const v = refs.cisco_advisory;
        if (typeof v === "string") ciscoIds.add(v.toUpperCase());
        else if (Array.isArray(v))
          for (const a of v)
            if (typeof a === "string") ciscoIds.add(a.toUpperCase());
      }
      // Also pick up a Cisco advisory id from the proposal filename.
      const m = f.match(/(cisco-sa-[a-z0-9-]+)\.proposal\.ya?ml$/i);
      if (m) ciscoIds.add(m[1].toUpperCase());
    }
  }
  return { cves, ciscoIds };
}

// ---------------------------------------------------------------------------
// Proposal renderer (逐欄 aligned with sync-aws-psirt / sync-ghsa renderProposal).
// ---------------------------------------------------------------------------
const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see publicationUrl for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function proposalId(a: CiscoAdvisory): string {
  // CVE id is the cross-source primary key; fall back to the Cisco advisory id.
  return a.cve_ids[0] ?? a.advisory_id;
}

function renderProposal(a: CiscoAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const pid = proposalId(a);
  const category = guessCategory(a.cwe_ids, `${a.title}\n${a.body}`);
  const triage = isDetectionReady(a);

  const responseActions =
    a.severity === "critical" || a.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock =
    a.cve_ids.length > 0
      ? `  cve:\n${a.cve_ids.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cweBlock =
    a.cwe_ids.length > 0
      ? `  cwe:\n${a.cwe_ids.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const ciscoBlock = `  cisco_advisory:\n    - "${a.advisory_id}"\n`;
  const externalUrl = a.publication_url || "https://sec.cloudapps.cisco.com/security/center/publicationListing.x";

  const title = a.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = a.body.replace(/\n+/g, " ").trim().slice(0, 600);

  return `# ATR rule proposal -- generated by scripts/sync-cisco-psirt.ts
# Source: Cisco PSIRT openVuln advisory ${a.advisory_id}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The full Cisco advisory
#         summary is attached under _cisco_psirt_sync.advisory_body for
#         conversion to precision-safe matchers.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${pid}
rule_version: 1
status: draft
description: >
  Cisco PSIRT advisory ${a.advisory_id}${a.cve_ids.length ? ` (${a.cve_ids.join(", ")})` : ""}.
  ${desc}
author: "ATR Community (Cisco PSIRT sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${a.severity}

references:
${cveBlock}${cweBlock}${ciscoBlock}  external:
    - "${externalUrl}"

metadata_provenance:
  cisco_psirt: cisco-psirt-sync
${a.cve_ids.length ? "  cve: cisco-psirt-sync\n" : ""}${a.cwe_ids.length ? "  cwe: cisco-psirt-sync\n" : ""}
tags:
  category: ${category}
  subcategory: cisco-psirt-imported
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
    # TODO(human): convert the Cisco advisory body (see
    # _cisco_psirt_sync.advisory_body) into precision-safe detection.conditions
    # regex/string matchers. Empty until a human reviewer promotes to rules/.
    []

response:
  actions:
${responseActions.map((act) => `    - ${act}`).join("\n")}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

# === sync-cisco-psirt.ts provenance ===
_cisco_psirt_sync:
  advisory_id: "${a.advisory_id}"
  cve_ids: ${JSON.stringify(a.cve_ids)}
  cwe_ids: ${JSON.stringify(a.cwe_ids)}
  bug_ids: ${JSON.stringify(a.bug_ids.slice(0, 20))}
  sir_severity: "${a.severity}"
  cvss_base_score: ${a.cvss_base_score ? `"${a.cvss_base_score}"` : "null"}
  product_names: ${JSON.stringify(a.product_names.slice(0, 20))}
  first_published: ${a.first_published ? `"${a.first_published.replace(/"/g, '\\"')}"` : "null"}
  last_updated: ${a.last_updated ? `"${a.last_updated.replace(/"/g, '\\"')}"` : "null"}
  publication_url: ${a.publication_url ? `"${a.publication_url}"` : "null"}
  data_source_used: "Cisco openVuln API ${ADVISORIES_ALL_URL}"
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(a.body || "(no summary in advisory)", "    ")}

# Triage flag read by promote-detection-ready.ts. Cisco advisories are usually
# prose (impact + fixed-release tables); the generator may only crystallize a
# rule when the body carries a concrete payload.
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
  advisories_seen: number;
  ai_product_hits: number;
  filtered_not_agent: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  written_files: string[];
  errors: string[];
}

function emitSummary(summary: RunSummary, dataSource: string | null): void {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::cisco-psirt-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      advisories_seen: summary.advisories_seen,
      ai_product_hits: summary.ai_product_hits,
      filtered_not_agent: summary.filtered_not_agent,
      already_known: summary.already_known,
      data_source_used: dataSource,
    })}`,
  );
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    advisories_seen: 0,
    ai_product_hits: 0,
    filtered_not_agent: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-cisco-psirt.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  // Secret discipline: creds from env ONLY. Missing -> exit 2 (recoverable).
  // This is the EXPECTED outcome in an environment with no Cisco creds.
  if (!CISCO_PSIRT_CLIENT_ID || !CISCO_PSIRT_CLIENT_SECRET) {
    console.error(
      "set CISCO_PSIRT_CLIENT_ID + CISCO_PSIRT_CLIENT_SECRET env to enable. " +
        "This source needs Cisco PSIRT openVuln API OAuth2 client-credentials " +
        "(free app registration at apiconsole.cisco.com). No --id / --secret " +
        "flags are accepted by design (secret discipline).",
    );
    summary.errors.push("CISCO_PSIRT_CLIENT_ID / CISCO_PSIRT_CLIENT_SECRET not set");
    emitSummary(summary, null);
    process.exit(2);
  }

  // --- OAuth2 client-credentials -> access token ---
  const token = await fetchAccessToken();
  if (!token) {
    // fetchAccessToken already printed a clear, secret-free message.
    summary.errors.push("Cisco OAuth token acquisition failed");
    emitSummary(summary, null);
    process.exit(2);
  }
  await sleep(CALL_DELAY_MS);

  // --- pull advisories ---
  let advisoriesRaw: CiscoAdvisoryRaw[] | null;
  try {
    advisoriesRaw = await fetchAllAdvisories(token);
  } catch (e) {
    // Schema mismatch / non-JSON -> fatal (1); network already handled as null.
    console.error(`fatal: ${(e as Error).message}`);
    summary.errors.push((e as Error).message);
    emitSummary(summary, null);
    process.exit(1);
  }
  if (advisoriesRaw === null) {
    // Auth-rejected / rate-limited / network — recoverable.
    summary.errors.push("Cisco advisories fetch returned no data (recoverable)");
    emitSummary(summary, null);
    process.exit(2);
  }

  const advisories = advisoriesRaw
    .map(normalizeAdvisory)
    .filter((a): a is CiscoAdvisory => a !== null);
  summary.advisories_seen = advisories.length;
  console.error(`openVuln /all: ${advisories.length} advisories`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const a of advisories) {
    if (writtenCount >= LIMIT) break;
    const searchText = `${a.title}\n${a.body}\n${a.product_names.join("\n")}`;

    // Gate 1 — Cisco AI/agent product keyword.
    const svc = ciscoAiProductHit(searchText);
    if (!svc) {
      if (VERBOSE)
        console.error(`  skip (not AI product) ${a.advisory_id}: ${a.title.slice(0, 50)}`);
      continue;
    }
    summary.ai_product_hits += 1;

    // Gate 2 — shared agentRelevance() from sync-ghsa (agent CWE OR keyword).
    const relevance = agentRelevance({
      summary: a.title,
      description: a.body,
      cwes: a.cwe_ids.map((c) => ({ cwe_id: c })),
    });
    if (!relevance.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(`  skip (not agent) ${a.advisory_id}: ${relevance.reason}`);
      continue;
    }

    // Dedup: CVE id OR Cisco advisory id already known.
    const cveHit = a.cve_ids.find((c) => known.cves.has(c));
    if (!FORCE && cveHit) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-rule ${cveHit}: already covered`);
      continue;
    }
    if (!FORCE && known.ciscoIds.has(a.advisory_id.toUpperCase())) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-rule ${a.advisory_id}: already covered`);
      continue;
    }

    const outName = `${proposalId(a)}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const triage = isDetectionReady(a);
    const body = renderProposal(a);

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(
        `  would write ${outName} [${a.cve_ids.join(",") || a.advisory_id}] (detection_ready=${triage.ready})`,
      );
      // Parse-check one rendered proposal so dry-run proves YAML validity.
      if (writtenCount === 0) {
        try {
          yaml.load(body);
          console.error(`    [self-check] sample proposal ${outName} parses OK (${body.length} bytes)`);
        } catch (e) {
          summary.errors.push(`yaml.load failed for ${outName}: ${(e as Error).message}`);
          console.error(`    [self-check] YAML PARSE ERROR: ${(e as Error).message}`);
        }
      }
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  emitSummary(summary, "Cisco openVuln API /all");
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
