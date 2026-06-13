#!/usr/bin/env npx tsx
/**
 * sync-vulnerablemcp.ts
 *
 * Pulls The Vulnerable MCP Project (vineethsai/vulnerablemcp) and emits ATR
 * rule proposals under proposals/vulnerablemcp/<CVE-or-entry-id>.proposal.yaml.
 *
 * Why this source: vulnerablemcp is a hand-curated catalog of Model Context
 * Protocol (MCP) attacks and CVEs — tool poisoning, line-jumping, rug pulls,
 * cross-server shadowing, MCP SSRF / DNS-rebinding / command-injection /
 * path-traversal RCEs, sandbox escapes, etc. It is 100% MCP-specific, so every
 * entry is in ATR scope (agent-runtime threat) by construction. Unlike the
 * GHSA / Huntr feeds, there is no ML-infra noise to gate out — the agentRelevance
 * second gate that sync-ghsa.ts needs is unnecessary here.
 *
 * Data source (verified 2026-06-12):
 *   - default branch: main
 *   - data: https://raw.githubusercontent.com/vineethsai/vulnerablemcp/main/data/vulnerabilities.json
 *           A JSON ARRAY (not {vulnerabilities:[]}) of ~50 entries.
 *   - taxonomy: https://raw.githubusercontent.com/vineethsai/vulnerablemcp/main/data/taxonomy.json
 *           Used to validate the source's own category ids for category mapping.
 *
 * Verified entry schema (per-entry, all 50 carry every field):
 *   id                 string   stable slug, e.g. "tool-poisoning-attacks",
 *                               "cve-2025-49596-..." — used as fallback proposal id
 *   title              string
 *   alternativeNames   string[]
 *   severity           "critical"|"high"|"medium"|"low"|"info"  (info -> low)
 *   category           string   one of taxonomy.categories ids (NOT ATR ids):
 *                               prompt-injection | input-validation |
 *                               authentication | session-management | integrity |
 *                               trust-model | credential-management |
 *                               network-security
 *   impactScore        number   1-10
 *   exploitability     string   "trivial"|"easy"|"moderate"|"theoretical"
 *                               (a label, NOT a numeric exploitabilityScore)
 *   affectedComponents string[] e.g. ["server","client"]
 *   prevalence         string
 *   reportedBy         string
 *   date               string   "YYYY-MM-DD"
 *   tags               string[]
 *   ciscoObjectives    string[]
 *   url                string   primary reference
 *   cveIds             string[] 0..n CVE ids (21/50 entries have >=1; 29 have 0)
 *   description        string
 *   who / where / when string   narrative prose
 *   how                string   attack-mechanism prose (sometimes inline payload)
 *   impact             string
 *   mitigation         string
 *   references         {title,url}[]   objects, NOT bare URL strings
 *
 * Reference-based DB: the actual exploit payloads live at the linked references
 * (blogs / advisories), not inline. Most entries are therefore detection_ready=false
 * (prose only). A handful embed payload-like content directly in description / how /
 * where / impact (command-injection strings, base64 blobs, curl invocations,
 * hidden-instruction markup) — those are flagged detection_ready=true so
 * promote-detection-ready.ts can crystallize them.
 *
 * Idempotency: skip if any of the entry's CVE ids, OR its source entry id, is
 * already covered in rules/ or proposals/, unless --force. CVE id is the
 * cross-source primary key.
 *
 * Usage:
 *   npx tsx scripts/sync-vulnerablemcp.ts                 # dry-run
 *   npx tsx scripts/sync-vulnerablemcp.ts --write         # write proposals
 *   npx tsx scripts/sync-vulnerablemcp.ts --force         # overwrite existing
 *   npx tsx scripts/sync-vulnerablemcp.ts --verbose
 *   npx tsx scripts/sync-vulnerablemcp.ts --limit 5
 *
 * Override the source URL (e.g. if the repo moves) via env VULNERABLEMCP_DATA_URL.
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path available (recoverable — source unreachable / empty)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "vulnerablemcp");

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

const DEFAULT_DATA_URL =
  "https://raw.githubusercontent.com/vineethsai/vulnerablemcp/main/data/vulnerabilities.json";
const DATA_URL = process.env.VULNERABLEMCP_DATA_URL || DEFAULT_DATA_URL;

// ---------------------------------------------------------------------------
// Category mapping.
// ---------------------------------------------------------------------------

// The source carries its OWN category taxonomy (8 ids, validated against
// taxonomy.json). Map each to the closest ATR category. This is the PRIMARY
// signal because every entry has a populated `category`.
const SOURCE_CATEGORY_TO_ATR: Record<string, string> = {
  "prompt-injection": "prompt-injection",
  "input-validation": "tool-poisoning",
  authentication: "privilege-escalation",
  "session-management": "context-exfiltration",
  integrity: "tool-poisoning",
  "trust-model": "tool-poisoning",
  "credential-management": "context-exfiltration",
  "network-security": "tool-poisoning",
};

// CWE → ATR category fallback (per shared contract — kept identical to
// sync-ghsa.ts). The vulnerablemcp data carries no CWE ids today, but a CVE
// id embedded in the entry may surface a CWE in future schema revisions, so the
// mapping path is preserved for forward-compat. No match → "model-abuse".
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

// Text-based detection — last fallback, mirrors sync-huntr's categoryForBounty.
function categoryFromText(haystack: string): string {
  const h = haystack.toLowerCase();
  if (/prompt[- ]injection|jailbreak|hidden instruction|tool description/.test(h))
    return "prompt-injection";
  if (/tool poisoning|tool-poisoning|rug pull|rug-pull|tool shadow|name collision|registry hijack/.test(h))
    return "tool-poisoning";
  if (/ssrf|server[- ]side[- ]request|dns rebinding|dns-rebinding/.test(h))
    return "tool-poisoning";
  if (/exfiltrat|context (leak|theft)|conversation history|credential (storage|leak)|data leak|history (theft|exposure)/.test(h))
    return "context-exfiltration";
  if (/path[- ]traversal|sandbox escape|sandbox-escape|info(rmation)?[- ](leak|disclos)/.test(h))
    return "context-exfiltration";
  if (/auth(entication)?[- ]bypass|unauthor(i[sz]ed|ised)|privilege|access control|consent fatigue/.test(h))
    return "privilege-escalation";
  if (/\brce\b|remote[- ]code[- ]exec|command[- ]injection|deserial|arbitrary code|code execution/.test(h))
    return "tool-poisoning";
  if (/excessive autonomy|over[- ]?privileged|too much autonomy/.test(h))
    return "excessive-autonomy";
  return "tool-poisoning";
}

function categoryForEntry(e: VmcpEntry, cwes: string[]): string {
  if (e.category && SOURCE_CATEGORY_TO_ATR[e.category])
    return SOURCE_CATEGORY_TO_ATR[e.category];
  for (const c of cwes) if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  return categoryFromText(
    `${e.title} ${e.description} ${e.how} ${(e.tags ?? []).join(" ")}`,
  );
}

// ---------------------------------------------------------------------------
// Source schema.
// ---------------------------------------------------------------------------

interface VmcpReference {
  title?: string;
  url?: string;
}

interface VmcpEntry {
  id: string;
  title: string;
  alternativeNames?: string[];
  severity?: string;
  category?: string;
  impactScore?: number;
  exploitability?: string;
  affectedComponents?: string[];
  prevalence?: string;
  reportedBy?: string;
  date?: string;
  tags?: string[];
  ciscoObjectives?: string[];
  url?: string;
  cveIds?: string[];
  description?: string;
  who?: string;
  where?: string;
  when?: string;
  how?: string;
  impact?: string;
  mitigation?: string;
  references?: VmcpReference[];
}

async function fetchData(): Promise<VmcpEntry[]> {
  const res = await fetch(DATA_URL, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok)
    throw new Error(
      `vulnerablemcp data fetch failed: ${res.status} ${res.statusText} (${DATA_URL})`,
    );
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`vulnerablemcp data is not valid JSON: ${(e as Error).message}`);
  }
  // The verified shape is a top-level array. Tolerate a {vulnerabilities:[]} or
  // {data:[]} wrapper in case the repo restructures.
  let list: unknown;
  if (Array.isArray(parsed)) list = parsed;
  else if (parsed && typeof parsed === "object") {
    const o = parsed as Record<string, unknown>;
    list = o.vulnerabilities ?? o.data ?? o.entries ?? null;
  }
  if (!Array.isArray(list))
    throw new Error(
      "vulnerablemcp data schema mismatch: expected a JSON array (or " +
        "{vulnerabilities|data|entries:[]}). Source may have restructured.",
    );
  return list.filter(
    (e): e is VmcpEntry =>
      !!e && typeof e === "object" && typeof (e as VmcpEntry).id === "string",
  );
}

// ---------------------------------------------------------------------------
// Severity normalization. Source uses "info" which ATR has no slot for -> low.
// ---------------------------------------------------------------------------

function parseSeverity(s: string | undefined): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  if (v === "info") return "low"; // ATR has no "info" severity
  return "medium";
}

// ---------------------------------------------------------------------------
// Detection-readiness triage. The DB is reference-based, so the default is
// false; flip to true only when an entry embeds payload-like content inline.
// ---------------------------------------------------------------------------

const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```", // fenced code block
    "payload:",
    "curl ",
    "wget ",
    "POST /[a-z]",
    "GET /[a-z]",
    "<script>",
    "<!--", // hidden HTML-comment instruction
    "<IMPORTANT>",
    "IMPORTANT:.*(assistant|llm|do not|must)",
    "\\$\\(", // command substitution
    "`[^`]+`", // backtick command substitution
    ";\\s*rm ",
    "os\\.system",
    "subprocess\\.",
    "eval\\(",
    "base64",
    "/etc/passwd",
    "~/.ssh",
    "id_rsa",
  ].join("|"),
  "im",
);

function isDetectionReady(e: VmcpEntry): { ready: boolean; reason: string } {
  const body = [e.how, e.description, e.where, e.impact]
    .filter((x): x is string => typeof x === "string")
    .join("\n");
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return {
      ready: true,
      reason: "payload-like content inline in description/how/where/impact",
    };
  return {
    ready: false,
    reason:
      "reference-based entry — payload lives at linked references, prose only inline",
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE ids and vulnerablemcp entry ids.
// ---------------------------------------------------------------------------

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const ent of readdirSync(dir)) {
    const f = join(dir, ent);
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (ent.endsWith(".yaml") || ent.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

interface KnownIndex {
  cves: Set<string>;
  entryIds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const entryIds = new Set<string>();
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
          references?: { cve?: string[]; vulnerablemcp_id?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.vulnerablemcp_id) {
        const v = refs.vulnerablemcp_id;
        if (typeof v === "string") entryIds.add(v);
        else if (Array.isArray(v))
          for (const h of v) if (typeof h === "string") entryIds.add(h);
      }
      // Also pick up the source entry id from the provenance block.
      const prov = (doc as { _vulnerablemcp_sync?: { entry_id?: string } })
        ?._vulnerablemcp_sync;
      if (prov?.entry_id && typeof prov.entry_id === "string")
        entryIds.add(prov.entry_id);
    }
  }
  return { cves, entryIds };
}

// ---------------------------------------------------------------------------
// Proposal renderer (column-for-column aligned with sync-huntr / sync-ghsa).
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

function buildAdvisoryBody(e: VmcpEntry): string {
  const parts: string[] = [];
  if (e.description) parts.push(`Description:\n${e.description}`);
  if (e.how) parts.push(`How (attack mechanism):\n${e.how}`);
  if (e.where) parts.push(`Where:\n${e.where}`);
  if (e.impact) parts.push(`Impact:\n${e.impact}`);
  if (e.mitigation) parts.push(`Mitigation:\n${e.mitigation}`);
  return parts.join("\n\n").trim() || "(no advisory body provided)";
}

export function renderProposal(e: VmcpEntry): string {
  const cveIds = (e.cveIds ?? []).filter(
    (c): c is string => typeof c === "string" && c.length > 0,
  );
  const primaryCve = cveIds[0] ?? null;
  const proposalId = primaryCve ?? e.id; // CVE id is primary key; else entry slug
  const cwes: string[] = []; // source carries no CWEs today
  const category = categoryForEntry(e, cwes);
  const severity = parseSeverity(e.severity);
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");

  const refUrls: string[] = [];
  if (e.url) refUrls.push(e.url);
  for (const r of e.references ?? [])
    if (r?.url && !refUrls.includes(r.url)) refUrls.push(r.url);

  const triage = isDetectionReady(e);
  const advisoryBody = buildAdvisoryBody(e);

  const responseActions =
    severity === "critical" || severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock =
    cveIds.length > 0
      ? `  cve:\n${cveIds.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cweBlock =
    cwes.length > 0
      ? `  cwe:\n${cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const vmcpBlock = `  vulnerablemcp_id:\n    - "${e.id}"\n`;
  const externalBlock =
    refUrls.length > 0
      ? `  external:\n${refUrls.map((u) => `    - "${u}"`).join("\n")}\n`
      : "";

  // Embed the advisory body as YAML comment lines under detection.conditions so
  // the human reviewer has the attack mechanism in front of them when converting
  // to a precision-safe regex (mirrors sync-huntr's PoC-comment convention).
  const advisoryCommentLines = advisoryBody
    .split("\n")
    .slice(0, 80)
    .map((s) => `    # ${s}`)
    .join("\n");

  const title = (e.title || e.id).replace(/"/g, '\\"').slice(0, 120);
  const descOneLine = (e.description || e.title || e.id)
    .replace(/\n+/g, " ")
    .trim()
    .slice(0, 600);
  const altNames = (e.alternativeNames ?? []).filter(
    (s): s is string => typeof s === "string",
  );

  return `# ATR rule proposal -- generated by scripts/sync-vulnerablemcp.ts
# Source: The Vulnerable MCP Project (vineethsai/vulnerablemcp) entry "${e.id}"
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The advisory body is
#         attached as a YAML comment under detection.conditions; the actual
#         exploit payload usually lives at the linked references.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  Vulnerable MCP Project entry ${e.id}${primaryCve ? ` (${primaryCve})` : ""}.
  MCP-specific ${category} threat${e.reportedBy ? `, reported by ${e.reportedBy}` : ""}.
  ${descOneLine}
author: "ATR Community (vulnerablemcp sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${cweBlock}${vmcpBlock}${externalBlock}

metadata_provenance:
  vulnerablemcp: vulnerablemcp-sync
${primaryCve ? "  cve: vulnerablemcp-sync\n" : ""}
tags:
  category: ${category}
  subcategory: mcp-catalog-imported
  scan_target: mcp
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
    # TODO(human): convert the advisory mechanism below into precision-safe
    # detection.conditions regex/string matchers. The exploit payload usually
    # lives at the linked references (this is a reference-based catalog), so
    # fetch those before writing patterns. Empty until promoted to rules/.
    #
    # === advisory body (from vineethsai/vulnerablemcp) ===
${advisoryCommentLines || "    # (no advisory body in source entry)"}
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

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"

# === sync-vulnerablemcp.ts provenance ===
_vulnerablemcp_sync:
  entry_id: "${e.id}"
  cve_ids: ${JSON.stringify(cveIds)}
  category_source: "${e.category ?? ""}"
  category_atr: "${category}"
  severity_source: "${e.severity ?? ""}"
  impact_score: ${typeof e.impactScore === "number" ? e.impactScore : "null"}
  exploitability: "${(e.exploitability ?? "").replace(/"/g, '\\"')}"
  affected_components: ${JSON.stringify(e.affectedComponents ?? [])}
  prevalence: "${(e.prevalence ?? "").replace(/"/g, '\\"')}"
  reported_by: "${(e.reportedBy ?? "").replace(/"/g, '\\"')}"
  disclosed_date: "${e.date ?? ""}"
  alternative_names: ${JSON.stringify(altNames)}
  tags: ${JSON.stringify(e.tags ?? [])}
  cisco_objectives: ${JSON.stringify(e.ciscoObjectives ?? [])}
  primary_url: "${(e.url ?? "").replace(/"/g, '\\"')}"
  imported_at: "${new Date().toISOString()}"
  data_source: "${DATA_URL}"
  advisory_body: |
${indentForLiteralBlock(advisoryBody, "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  data_source: string;
  entries_scanned: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  skipped_existing: number;
  errors: string[];
  written_files: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    data_source: DATA_URL,
    entries_scanned: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    skipped_existing: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-vulnerablemcp.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`source: ${DATA_URL}`);

  let entries: VmcpEntry[];
  try {
    entries = await fetchData();
  } catch (e) {
    summary.errors.push(`fetch/parse: ${(e as Error).message}`);
    console.error(`fatal-or-recoverable: ${(e as Error).message}`);
    // Network/unreachable -> recoverable (exit 2); schema mismatch -> fatal.
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::vulnerablemcp-summary::${JSON.stringify({
        new_proposals: 0,
        entries_scanned: 0,
        new_detection_ready: 0,
        new_tracking_only: 0,
        data_source: DATA_URL,
        error: (e as Error).message,
      })}`,
    );
    process.exit(/schema mismatch|not valid JSON/.test((e as Error).message) ? 1 : 2);
  }

  summary.entries_scanned = entries.length;
  console.error(`fetched ${entries.length} entries`);

  if (entries.length === 0) {
    summary.errors.push("source returned 0 entries (recoverable)");
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::vulnerablemcp-summary::${JSON.stringify({
        new_proposals: 0,
        entries_scanned: 0,
        new_detection_ready: 0,
        new_tracking_only: 0,
        data_source: DATA_URL,
      })}`,
    );
    process.exit(2);
  }

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const e of entries) {
    if (writtenCount >= LIMIT) break;

    const cveIds = (e.cveIds ?? []).filter(
      (c): c is string => typeof c === "string" && c.length > 0,
    );

    // Dedup: any covered CVE, or the source entry id already imported.
    if (!FORCE) {
      const dupCve = cveIds.find((c) => known.cves.has(c));
      if (dupCve) {
        summary.skipped_existing += 1;
        if (VERBOSE) console.error(`  have-rule ${e.id}: CVE ${dupCve} already covered`);
        continue;
      }
      if (known.entryIds.has(e.id)) {
        summary.skipped_existing += 1;
        if (VERBOSE) console.error(`  have-rule ${e.id}: entry already imported`);
        continue;
      }
    }

    const proposalId = cveIds[0] ?? e.id;
    const outName = `${proposalId}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const triage = isDetectionReady(e);
    const body = renderProposal(e);

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}${triage.ready ? " [detection-ready]" : ""}`);
    } else {
      console.error(
        `  would write ${outName}${triage.ready ? " [detection-ready]" : ""}`,
      );
    }

    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  // Sanity: parse the last rendered proposal so a dry-run proves output is
  // valid YAML before any --write run touches disk.
  if (summary.new_proposals > 0 && VERBOSE) {
    const sampleEntry = entries.find((e) => {
      const cveIds = (e.cveIds ?? []).filter(
        (c): c is string => typeof c === "string" && c.length > 0,
      );
      if (!FORCE) {
        if (cveIds.find((c) => known.cves.has(c))) return false;
        if (known.entryIds.has(e.id)) return false;
      }
      return true;
    });
    if (sampleEntry) {
      try {
        const parsed = yaml.load(renderProposal(sampleEntry));
        const ok =
          parsed && typeof parsed === "object" && "id" in (parsed as object);
        console.error(
          `sample-parse: ${(sampleEntry.cveIds?.[0] ?? sampleEntry.id)} -> ${ok ? "valid YAML" : "PARSED-BUT-UNEXPECTED-SHAPE"}`,
        );
      } catch (err) {
        console.error(`sample-parse FAILED: ${(err as Error).message}`);
        summary.errors.push(`sample-parse: ${(err as Error).message}`);
      }
    }
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::vulnerablemcp-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      entries_scanned: summary.entries_scanned,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      skipped_existing: summary.skipped_existing,
      data_source: DATA_URL,
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
