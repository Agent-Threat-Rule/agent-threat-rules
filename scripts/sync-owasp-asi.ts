#!/usr/bin/env npx tsx
/**
 * sync-owasp-asi.ts
 *
 * Pulls the OWASP Agentic AI Security Incidents tracker and emits ATR rule
 * proposals under proposals/owasp-asi/<id>.proposal.yaml.
 *
 * WHY THIS SOURCE: unlike GHSA / CISA-KEV / OSV (which sync-ghsa.ts and
 * sync-cisa-kev.ts already cover), this tracker catalogues AGENT BEHAVIOR
 * incidents that pure CVE feeds miss -- indirect prompt injection, tool /
 * connector poisoning, memory & context poisoning, identity & privilege
 * abuse, insecure inter-agent communication. Many entries have a CVE; many
 * (the curated real-world agent incidents) do not. Those CVE-less narratives
 * are the unique value here.
 *
 * DATA SOURCE (verified 2026-06-12):
 *   Frontend:  https://owasp-agentic-ai-security-incidents.lovable.app/
 *              (a Lovable-hosted SPA -- no incident data in initial HTML).
 *   Backend:   The SPA syncs daily from a curated incident dataset. The
 *              OWASP-ASI GitHub org itself (github.com/OWASP-ASI) holds ONLY
 *              the FinBot CTF demo repos -- NO incident dataset. The actual
 *              machine-readable dataset is the community "single source of
 *              truth for GenAI and agentic AI security incidents, mapped to
 *              OWASP LLM Top 10 + OWASP Agentic Top 10 (ASI)":
 *                emmanuelgjr/genai_incidents -> data/incidents.json
 *              (raw.githubusercontent.com/.../main/data/incidents.json),
 *              ~11.6k incidents, each with owasp_asi[], attack_vector,
 *              cve_ids[], cwe_ids[], severity, references[], description,
 *              tier (landmark|feed), quality_tier (curated|reviewed|auto).
 *              A mirror with the SAME schema lives at the homepage
 *              emmanuelgjr.github.io/genai_incidents/data/incidents.min.json.
 *
 * If the dataset URL ever moves, a maintainer can override it via env var
 * OWASP_ASI_DATA_URL (must point at JSON with the same {incidents:[...]}
 * schema). If NO machine-readable dataset can be fetched, the script exits 2
 * (recoverable) naming exactly what it tried -- it never fabricates a path.
 *
 * SCOPE GATE (per the shared contract -- do NOT widen ATR scope): ATR detects
 * AGENT-RUNTIME threats. This source carries 11.6k incidents including pure
 * AI-harm (deepfakes, misinformation, bias, CSAM, privacy-policy violations)
 * and the full GHSA/OSV CVE firehose. We drop:
 *   - corpus == "ai-harm" (societal harm, no security primitive)
 *   - harm-only attack vectors (deepfake / misinformation / bias / csam /
 *     unsafe-advice / malware) with no agent-runtime ASI mapping
 *   - incidents with NO agent-runtime ASI class AND no agent-relevant
 *     attack_vector / CWE
 * and KEEP an incident only if it maps to an agent-runtime ASI class
 * (ASI01-ASI07) OR carries an agent-relevant attack_vector / CWE. This is the
 * analogue of sync-ghsa.ts's agentRelevance() second gate.
 *
 * ORDERING: landmark / curated / reviewed incidents are processed first so a
 * small --limit surfaces the high-value agent-behavior incidents (which the
 * CVE feeds miss) before the CVE-stream tail (which they already cover).
 *
 * Each proposal:
 *   - id: CVE-id if present (cve_ids[0]), else OWASP-ASI-<INC-id>.
 *   - status=draft, maturity=experimental, detection_tier=pattern.
 *   - tags.category from ASI class (primary) refined by CWE, falling back to
 *     attack_vector / text, final fallback model-abuse.
 *   - detection.conditions EMPTY with a TODO + the incident narrative attached
 *     as a YAML comment so the human reviewer has the attack story.
 *   - _owasp_asi_sync.advisory_body holds the FULL incident narrative
 *     (description + attack_vector + impact) -- the payload source for
 *     promote-detection-ready.ts.
 *   - _triage.detection_ready true ONLY if an inline payload / code block /
 *     concrete attack string exists; incident prose -> false.
 *
 * Idempotency: skip if the CVE-id OR the incident id is already covered in
 * rules/ or proposals/, unless --force.
 *
 * Usage:
 *   npx tsx scripts/sync-owasp-asi.ts                 # dry-run
 *   npx tsx scripts/sync-owasp-asi.ts --write         # write proposals
 *   npx tsx scripts/sync-owasp-asi.ts --force         # overwrite existing
 *   npx tsx scripts/sync-owasp-asi.ts --verbose
 *   npx tsx scripts/sync-owasp-asi.ts --limit 25
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network down on every endpoint, schema mismatch)
 *   2 no machine-readable dataset available (recoverable)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "owasp-asi");

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

// Frontend (human-facing tracker) -- always added to references.external so a
// reviewer can find the live incident card.
const TRACKER_URL = "https://owasp-agentic-ai-security-incidents.lovable.app/";

// Candidate machine-readable dataset endpoints, tried in order. A maintainer
// may override via OWASP_ASI_DATA_URL. These are NOT secrets (public JSON);
// no API key is required for this source.
const DATA_URLS: string[] = [
  process.env.OWASP_ASI_DATA_URL,
  "https://raw.githubusercontent.com/emmanuelgjr/genai_incidents/main/data/incidents.json",
  "https://emmanuelgjr.github.io/genai_incidents/data/incidents.min.json",
].filter((u): u is string => typeof u === "string" && u.length > 0);

// ---------------------------------------------------------------------------
// Source schema (subset we consume). Unknown fields are ignored.
// ---------------------------------------------------------------------------

interface SourceReference {
  title?: string;
  url?: string;
  type?: string;
}

interface SourceIncident {
  id: string; // "INC-#####"
  source_ids?: string[];
  title?: string;
  description?: string;
  date?: string;
  year?: number;
  category?: string;
  attack_vector?: string;
  affected?: string;
  impact?: string;
  severity?: string; // "Critical" | "High" | "Medium" | "Low" | "Info"
  owasp_asi?: string[] | string;
  owasp_llm?: string[];
  cve_ids?: string[];
  cwe_ids?: string[];
  references?: SourceReference[];
  tags?: string[];
  corpus?: string; // "security" | "ai-harm"
  tier?: string; // "landmark" | "feed"
  quality_tier?: string; // "curated" | "reviewed" | "auto"
  mitre_atlas?: string[];
  added?: string;
  updated?: string;
}

interface SourceDataset {
  version?: string;
  generated?: string;
  incident_count?: number;
  incidents: SourceIncident[];
}

// ---------------------------------------------------------------------------
// Taxonomy maps.
// ---------------------------------------------------------------------------

// OWASP ASI (Agentic) Top 10 -> ATR category. Primary signal.
//   ASI01 Agent Goal Hijack                -> prompt-injection
//   ASI02 Tool Misuse & Exploitation       -> tool-poisoning
//   ASI03 Identity & Privilege Abuse       -> privilege-escalation
//   ASI04 Agentic Supply Chain Vuln        -> tool-poisoning
//   ASI05 Unexpected Code Execution (RCE)  -> tool-poisoning
//   ASI06 Memory & Context Poisoning       -> data-poisoning
//   ASI07 Insecure Inter-Agent Comms       -> context-exfiltration
//   ASI08 Cascading Failures               -> model-abuse  (not runtime gate)
//   ASI09 Human-Agent Trust Exploitation   -> model-abuse  (not runtime gate)
//   ASI10 Rogue Agents                     -> model-abuse  (not runtime gate)
const ASI_TO_CATEGORY: Record<string, string> = {
  ASI01: "prompt-injection",
  ASI02: "tool-poisoning",
  ASI03: "privilege-escalation",
  ASI04: "tool-poisoning",
  ASI05: "tool-poisoning",
  ASI06: "data-poisoning",
  ASI07: "context-exfiltration",
  ASI08: "model-abuse",
  ASI09: "model-abuse",
  ASI10: "model-abuse",
};

// ASI classes that represent an agent-RUNTIME threat ATR can write a content
// rule for. ASI08/09/10 (cascading failure, human trust, rogue agents) are
// real but are NOT a content-layer detection target, so they do not by
// themselves pass the relevance gate (an agent-relevant attack_vector / CWE
// can still keep them).
const AGENT_RUNTIME_ASI = new Set([
  "ASI01",
  "ASI02",
  "ASI03",
  "ASI04",
  "ASI05",
  "ASI06",
  "ASI07",
]);

// CWE -> ATR category (verbatim from sync-ghsa.ts). Used to refine the
// ASI-derived category when the incident carries a CWE.
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

// Agent-relevant attack vectors (the tracker's controlled vocabulary). These
// are content-layer agent-runtime threats ATR can target.
const AGENT_RELEVANT_VECTORS = new Set([
  "prompt-injection",
  "indirect-prompt-injection",
  "jailbreak",
  "rce",
  "command-injection",
  "deserialization",
  "ssrf",
  "path-traversal",
  "sql-injection",
  "xss",
  "data-exfiltration",
  "info-disclosure",
  "auth-bypass",
  "adversarial-input",
  "tool-poisoning",
  "memory-poisoning",
]);

// Pure AI-harm vectors with no agent-runtime security primitive. Even if they
// somehow carry an ASI tag, drop them -- they are the noise class the contract
// warns about (the deepfake/misinformation analogue of TensorFlow kernel
// crashes in sync-ghsa.ts).
const HARM_ONLY_VECTORS = new Set([
  "deepfake",
  "misinformation",
  "algorithmic-bias",
  "csam-generation",
  "privacy-violation",
  "unsafe-advice",
]);

function asiList(inc: SourceIncident): string[] {
  const v = inc.owasp_asi;
  if (Array.isArray(v)) return v.filter((s) => typeof s === "string");
  if (typeof v === "string" && v) return [v];
  return [];
}

// Second gate (after we already restrict to the tracker): is THIS incident an
// agent-runtime threat ATR could write a detection rule for?
function agentRelevance(inc: SourceIncident): {
  relevant: boolean;
  reason: string;
} {
  if (inc.corpus === "ai-harm")
    return { relevant: false, reason: "corpus=ai-harm (societal harm)" };

  const av = (inc.attack_vector || "").toLowerCase();
  if (HARM_ONLY_VECTORS.has(av))
    return { relevant: false, reason: `harm-only vector ${av}` };

  const asi = asiList(inc);
  const hitAsi = asi.find((a) => AGENT_RUNTIME_ASI.has(a));
  if (hitAsi)
    return { relevant: true, reason: `agent-runtime ${hitAsi}` };

  if (AGENT_RELEVANT_VECTORS.has(av))
    return { relevant: true, reason: `agent-relevant vector ${av}` };

  const cwes = (inc.cwe_ids ?? []).map((c) => c.toUpperCase());
  const hitCwe = cwes.find((c) => CWE_TO_CATEGORY[c]);
  if (hitCwe) return { relevant: true, reason: `agent-relevant ${hitCwe}` };

  return {
    relevant: false,
    reason: `no agent-runtime ASI / vector / CWE (asi: ${asi.join(",") || "none"}, vector: ${av || "none"})`,
  };
}

// Text-based category fallback (sync-huntr categoryForBounty analogue).
function categoryFromText(inc: SourceIncident): string {
  const haystack =
    `${inc.title ?? ""} ${inc.description ?? ""} ${inc.attack_vector ?? ""} ${(inc.tags ?? []).join(" ")}`.toLowerCase();
  if (/prompt[- ]injection|jailbreak|goal[- ]hijack/.test(haystack))
    return "prompt-injection";
  if (/ssrf|server[- ]side[- ]request[- ]forgery/.test(haystack))
    return "context-exfiltration";
  if (/exfiltrat|data[- ]leak|info(rmation)?[- ](leak|disclos)|path[- ]traversal|lfi/.test(haystack))
    return "context-exfiltration";
  if (/memory[- ]poison|context[- ]poison|data[- ]poison/.test(haystack))
    return "data-poisoning";
  if (/auth(entication)?[- ]bypass|privilege|unauthor(i[sz]ed|ised)/.test(haystack))
    return "privilege-escalation";
  if (/\brce\b|remote[- ]code[- ]exec|command[- ]injection|deserial|pickle|tool[- ](misuse|poison)|supply[- ]chain/.test(haystack))
    return "tool-poisoning";
  return "model-abuse";
}

// Resolve the ATR category: ASI class first, refined by CWE if the CWE map
// gives a more specific answer, then text fallback, final fallback model-abuse.
function resolveCategory(inc: SourceIncident): string {
  const asi = asiList(inc);
  const asiHit = asi.map((a) => ASI_TO_CATEGORY[a]).find(Boolean);
  const cwes = (inc.cwe_ids ?? []).map((c) => c.toUpperCase());
  const cweHit = cwes.map((c) => CWE_TO_CATEGORY[c]).find(Boolean);
  // Prefer a runtime-specific ASI category; if it resolved only to the generic
  // model-abuse (ASI08/09/10) but a CWE gives something sharper, use the CWE.
  if (asiHit && asiHit !== "model-abuse") return asiHit;
  if (cweHit) return cweHit;
  if (asiHit) return asiHit;
  return categoryFromText(inc);
}

function normalizeSeverity(
  s: string | undefined,
): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  // "info" / unknown -> low so response.actions stays alert-only.
  return "low";
}

// ---------------------------------------------------------------------------
// detection_ready triage. These are incident narratives (prose) -- almost
// always FALSE. True only if the body carries an inline payload / code block /
// concrete attack string.
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
    "\\bimport os\\b",
    "subprocess\\.",
    "os\\.system",
    "__import__",
  ].join("|"),
  "im",
);

function buildAdvisoryBody(inc: SourceIncident): string {
  const parts: string[] = [];
  if (inc.description) parts.push(inc.description.trim());
  if (inc.attack_vector)
    parts.push(`Attack vector: ${inc.attack_vector}`);
  if (inc.affected) parts.push(`Affected: ${inc.affected}`);
  if (inc.impact) parts.push(`Impact: ${inc.impact}`);
  return parts.join("\n\n");
}

function isDetectionReady(advisoryBody: string): {
  ready: boolean;
  reason: string;
} {
  if (PAYLOAD_HEURISTICS_RX.test(advisoryBody))
    return { ready: true, reason: "inline payload / code block in incident body" };
  return {
    ready: false,
    reason: "incident narrative is prose-only (no inline payload)",
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE / incident ids across rules/ and proposals/.
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
  incidents: Set<string>; // INC-##### ids
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const incidents = new Set<string>();
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
        doc as { references?: { cve?: string[] } }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      // Our own provenance block carries the incident id.
      const prov = (
        doc as { _owasp_asi_sync?: { incident_id?: string } }
      )?._owasp_asi_sync;
      if (prov?.incident_id && typeof prov.incident_id === "string")
        incidents.add(prov.incident_id);
      // Also pick up incident ids from our filename pattern.
      const m = f.match(/OWASP-ASI-(INC-\d+)/i);
      if (m) incidents.add(m[1]);
    }
  }
  return { cves, incidents };
}

// ---------------------------------------------------------------------------
// Dataset fetch.
// ---------------------------------------------------------------------------

async function fetchDataset(): Promise<{
  ok: boolean;
  url: string | null;
  dataset: SourceDataset | null;
  tried: string[];
  reason: string;
}> {
  const tried: string[] = [];
  for (const url of DATA_URLS) {
    tried.push(url);
    try {
      const res = await fetch(url, { headers: { "User-Agent": POLITE_UA } });
      if (!res.ok) {
        if (VERBOSE)
          console.error(`  data probe ${url} -> ${res.status} ${res.statusText}`);
        continue;
      }
      const text = await res.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch (e) {
        if (VERBOSE)
          console.error(`  data probe ${url} -> not JSON: ${(e as Error).message}`);
        continue;
      }
      const ds = parsed as SourceDataset;
      if (!ds || !Array.isArray(ds.incidents)) {
        if (VERBOSE)
          console.error(`  data probe ${url} -> JSON has no incidents[]`);
        continue;
      }
      return { ok: true, url, dataset: ds, tried, reason: "ok" };
    } catch (e) {
      if (VERBOSE) console.error(`  data probe ${url} -> ${(e as Error).message}`);
    }
  }
  return {
    ok: false,
    url: null,
    dataset: null,
    tried,
    reason:
      "no machine-readable incident dataset reachable. Tried: " +
      tried.join(", ") +
      ". The OWASP-ASI GitHub org (github.com/OWASP-ASI) holds only FinBot " +
      "CTF demo repos -- no incident dataset. Set OWASP_ASI_DATA_URL to a " +
      "JSON endpoint with an {incidents:[...]} schema to override.",
  };
}

// Sort high-value agent-behavior incidents first so a small --limit surfaces
// the entries CVE feeds miss (landmark + curated/reviewed) before the CVE tail.
function priorityRank(inc: SourceIncident): number {
  let r = 0;
  if (inc.tier === "landmark") r += 4;
  if (inc.quality_tier === "curated") r += 3;
  else if (inc.quality_tier === "reviewed") r += 1;
  if (!inc.cve_ids || inc.cve_ids.length === 0) r += 2; // CVE-less = unique value
  return r;
}

// ---------------------------------------------------------------------------
// Proposal renderer (field-for-field aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see tracker URL for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function externalRefUrls(inc: SourceIncident): string[] {
  const urls = (inc.references ?? [])
    .map((r) => r?.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
  // Always include the live tracker so a reviewer can open the incident card.
  urls.push(TRACKER_URL);
  // de-dup, preserve order
  return Array.from(new Set(urls));
}

function renderProposal(inc: SourceIncident): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");

  const cveId = inc.cve_ids && inc.cve_ids.length > 0 ? inc.cve_ids[0] : null;
  const proposalId = cveId ?? `OWASP-ASI-${inc.id}`;
  const category = resolveCategory(inc);
  const severity = normalizeSeverity(inc.severity);
  const asi = asiList(inc);
  const cwes = (inc.cwe_ids ?? []).map((c) => c.toUpperCase());
  const advisoryBody = buildAdvisoryBody(inc);
  const triage = isDetectionReady(advisoryBody);

  const responseActions =
    severity === "critical" || severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const title = (inc.title || inc.id).replace(/"/g, '\\"').slice(0, 120);
  const descOneLine = (inc.description || inc.title || inc.id)
    .replace(/\n+/g, " ")
    .trim()
    .slice(0, 600);

  const cveBlock = cveId
    ? `  cve:\n${inc.cve_ids!.map((c) => `    - "${c}"`).join("\n")}\n`
    : "";
  const cweBlock =
    cwes.length > 0
      ? `  cwe:\n${cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const externalBlock = `  external:\n${externalRefUrls(inc)
    .map((u) => `    - "${u}"`)
    .join("\n")}\n`;

  // Incident narrative attached as YAML comment lines under conditions so the
  // human reviewer has the attack story without re-fetching the source.
  const narrativeComment = advisoryBody
    .split("\n")
    .filter((s) => s.trim().length > 0)
    .slice(0, 60)
    .map((s) => `    # ${s}`)
    .join("\n");

  return `# ATR rule proposal -- generated by scripts/sync-owasp-asi.ts
# Source: OWASP Agentic AI Security Incidents tracker (incident ${inc.id})
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The incident narrative
#         is attached as a YAML comment under detection.conditions for ease of
#         conversion to a precision-safe matcher (most incidents are prose, so
#         detection_ready is usually false -- tracking-only until a payload is
#         identified).
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  OWASP Agentic AI Security Incident ${inc.id}${cveId ? ` (${cveId})` : ""}.
  OWASP ASI: ${asi.join(", ") || "unmapped"}.
  ${descOneLine}
author: "ATR Community (OWASP-ASI sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${cweBlock}${externalBlock}
metadata_provenance:
  owasp_asi: owasp-asi-sync
${cveId ? "  cve: owasp-asi-sync\n" : ""}${cwes.length ? "  cwe: owasp-asi-sync\n" : ""}
tags:
  category: ${category}
  subcategory: owasp-asi-incident
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
    # TODO(human): convert the incident narrative below into precision-safe
    # detection.conditions regex/string matchers. Without this work the rule
    # will neither fire nor be promotable to rules/.
    #
    # === OWASP-ASI incident narrative ===
${narrativeComment || "    # (no narrative in source incident)"}
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

confidence: ${triage.ready ? 70 : 50}

test_cases:
  true_positives: []
  true_negatives: []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"

# === sync-owasp-asi.ts provenance ===
_owasp_asi_sync:
  incident_id: "${inc.id}"
  cve_ids: ${JSON.stringify(inc.cve_ids ?? [])}
  cwe_ids: ${JSON.stringify(cwes)}
  owasp_asi: ${JSON.stringify(asi)}
  owasp_llm: ${JSON.stringify(inc.owasp_llm ?? [])}
  mitre_atlas: ${JSON.stringify(inc.mitre_atlas ?? [])}
  attack_vector: "${(inc.attack_vector ?? "").replace(/"/g, '\\"')}"
  affected: "${(inc.affected ?? "").replace(/"/g, '\\"').slice(0, 300)}"
  severity: "${inc.severity ?? ""}"
  category: "${inc.category ?? ""}"
  tier: "${inc.tier ?? ""}"
  quality_tier: "${inc.quality_tier ?? ""}"
  incident_date: "${inc.date ?? ""}"
  tracker_url: "${TRACKER_URL}"
  imported_at: "${new Date().toISOString()}"
  data_source_used: "emmanuelgjr/genai_incidents data/incidents.json"
  advisory_body: |
${indentForLiteralBlock(advisoryBody || "(no narrative provided)", "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  data_source_used: string | null;
  dataset_version: string | null;
  incidents_total: number;
  incidents_agent_relevant: number;
  filtered_not_agent: number;
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
    data_source_used: null,
    dataset_version: null,
    incidents_total: 0,
    incidents_agent_relevant: 0,
    filtered_not_agent: 0,
    skipped_existing: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-owasp-asi.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  const fetched = await fetchDataset();
  if (!fetched.ok || !fetched.dataset) {
    summary.errors.push(fetched.reason);
    console.error(fetched.reason);
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::owasp-asi-summary::${JSON.stringify({
        new_proposals: 0,
        incidents_total: 0,
        incidents_agent_relevant: 0,
        data_source_used: null,
        tried: fetched.tried,
      })}`,
    );
    process.exit(2);
  }

  const ds = fetched.dataset;
  summary.data_source_used = fetched.url;
  summary.dataset_version = ds.version ?? null;
  summary.incidents_total = ds.incidents.length;
  console.error(
    `data source: ${fetched.url} (version ${ds.version ?? "?"}, ${ds.incidents.length} incidents)`,
  );

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // Filter to agent-runtime relevant incidents, then prioritise the
  // high-value agent-behavior set (landmark / curated / CVE-less).
  const relevant: SourceIncident[] = [];
  for (const inc of ds.incidents) {
    if (!inc || typeof inc.id !== "string") continue;
    const rel = agentRelevance(inc);
    if (!rel.relevant) {
      summary.filtered_not_agent += 1;
      continue;
    }
    relevant.push(inc);
  }
  summary.incidents_agent_relevant = relevant.length;
  relevant.sort((a, b) => priorityRank(b) - priorityRank(a));
  console.error(
    `agent-relevant: ${relevant.length} of ${ds.incidents.length} ` +
      `(dropped ${summary.filtered_not_agent} non-agent / harm-only)`,
  );

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const inc of relevant) {
    if (writtenCount >= LIMIT) break;

    const cveId = inc.cve_ids && inc.cve_ids.length > 0 ? inc.cve_ids[0] : null;
    const proposalId = cveId ?? `OWASP-ASI-${inc.id}`;

    // Dedup: CVE id is the cross-source primary key; incident id is the
    // source-native key.
    if (!FORCE && cveId && known.cves.has(cveId)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-rule ${cveId}: already covered`);
      continue;
    }
    if (!FORCE && known.incidents.has(inc.id)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-rule ${inc.id}: already covered`);
      continue;
    }

    const outName = `${proposalId}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const body = renderProposal(inc);
    const advisoryBody = buildAdvisoryBody(inc);
    const triage = isDetectionReady(advisoryBody);

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(
        `  would write ${outName} [${triage.ready ? "READY" : "tracking"}] ` +
          `cat=${resolveCategory(inc)} asi=${asiList(inc).join(",") || "-"}`,
      );
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  // Dry-run self-check: yaml.load one rendered sample to prove parseability.
  if (!WRITE && relevant.length > 0) {
    const sample = renderProposal(relevant[0]);
    try {
      const parsed = yaml.load(sample);
      const id = (parsed as { id?: string })?.id;
      console.error(`sample parse OK -> id=${id}`);
    } catch (e) {
      summary.errors.push(`sample yaml parse failed: ${(e as Error).message}`);
      console.error(`sample yaml parse FAILED: ${(e as Error).message}`);
    }
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::owasp-asi-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      incidents_total: summary.incidents_total,
      incidents_agent_relevant: summary.incidents_agent_relevant,
      filtered_not_agent: summary.filtered_not_agent,
      skipped_existing: summary.skipped_existing,
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
