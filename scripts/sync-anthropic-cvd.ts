#!/usr/bin/env npx tsx
/**
 * sync-anthropic-cvd.ts
 *
 * Pulls Anthropic's Coordinated Vulnerability Disclosure (CVD) ledger and
 * emits ATR rule proposals under
 * proposals/anthropic-cvd/<CVE-id-or-ANTHROPIC-CVD-slug>.proposal.yaml.
 *
 * BACKGROUND
 *   Anthropic ran a program (Project Glasswing / Claude red-team) where Claude
 *   discovered vulnerabilities in widely-used open-source software and ran them
 *   through coordinated disclosure. Findings that were revealed publicly (after
 *   patch or after the 90-day window) are published on a dashboard at
 *   https://red.anthropic.com/2026/cvd/ , many with assigned CVE / GHSA ids.
 *
 * DATA SOURCE (verified live 2026-06-12)
 *   The dashboard is backed by a single machine-readable file:
 *       https://red.anthropic.com/2026/cvd/data/payload.json   (HTTP 200, ~1 MB)
 *   The page footer even cites it ("Manifest hash ... data/payload.json"), so
 *   this is the intended programmatic surface — no HTML scraping needed.
 *
 *   Shape (top-level keys we use):
 *     cve_records:  [ { identifier: "CVE-2026-...", kind: "cve",
 *                       revealed_at, findings: [ { ant_id, bug_class,
 *                       project, severity, title } ] } ]
 *     ghsa_records: same shape with identifier: "GHSA-..." , kind: "ghsa"
 *     ledger:       1611 entries, MOST redacted (project/ant_id null,
 *                   cve_ids: []). Only the ~27 `reveal_tier: "revealed"`
 *                   entries carry project + cve_ids/ghsa_ids + patch status.
 *                   We use the ledger only to ENRICH cve/ghsa records (patch
 *                   status, claude/vendor severity) keyed by ant_id; the
 *                   cve_records / ghsa_records lists are the spine because they
 *                   carry the bug_class + title text we triage on.
 *
 *   If the payload ever moves or the schema changes, the script exits 2
 *   (recoverable) with a message naming exactly what it fetched and why it
 *   could not parse — it never fabricates a feed.
 *
 * ATR SCOPE (important — this source is mostly out of ATR scope, by design)
 *   These are general OSS vulnerabilities (nginx, wolfSSL, freerdp, ImageMagick,
 *   libyang, jq ...). The dominant bug class is heap-buffer-overflow and other
 *   memory-safety / availability bugs that ATR (an AGENT-runtime threat standard)
 *   deliberately does NOT detect. We therefore reuse sync-ghsa.ts's two gates:
 *     1. ML-infra package exclusion (no extra ML list added).
 *     2. agentRelevance() — keep only advisories carrying an agent-relevant CWE
 *        or an agent-threat keyword (injection / exec / exfil / SSRF / path
 *        traversal / auth bypass). Memory-safety crashes are dropped.
 *   The honest outcome is that only a handful (rce / ssrf / sql-injection /
 *   command-injection / path-traversal / broken-access-control / file-write)
 *   survive the gate. That is correct, not a bug.
 *
 *   detection_ready is false for all of these: the dashboard titles are prose
 *   descriptions, not inline payloads, so there is nothing for
 *   promote-detection-ready.ts to crystallize yet. The full advisory text we
 *   have (title + bug_class + project) is preserved under
 *   `_anthropic_cvd_sync.advisory_body` for the human reviewer.
 *
 * Usage:
 *   npx tsx scripts/sync-anthropic-cvd.ts                 # dry-run
 *   npx tsx scripts/sync-anthropic-cvd.ts --write         # write proposals
 *   npx tsx scripts/sync-anthropic-cvd.ts --force         # overwrite existing
 *   npx tsx scripts/sync-anthropic-cvd.ts --verbose
 *   npx tsx scripts/sync-anthropic-cvd.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network down, unrecoverable)
 *   2 no data path available (recoverable -- payload moved / schema changed)
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
import { agentRelevance } from "./sync-ghsa.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "anthropic-cvd");

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

// Source of truth. Overridable via env for a maintainer who needs to point at a
// mirror or a newer year path, but defaults to the verified live location.
const CVD_PAYLOAD_URL =
  process.env.ANTHROPIC_CVD_URL ||
  "https://red.anthropic.com/2026/cvd/data/payload.json";
const CVD_DASHBOARD_URL = "https://red.anthropic.com/2026/cvd/";

// ---------------------------------------------------------------------------
// payload.json types (only the fields we read).
// ---------------------------------------------------------------------------

interface CvdFinding {
  ant_id: string | null;
  bug_class: string | null;
  project: string | null;
  severity: string | null;
  title: string | null;
}

interface CvdRecord {
  identifier: string; // CVE-... or GHSA-...
  kind: "cve" | "ghsa" | string;
  revealed_at: string | null;
  findings: CvdFinding[];
}

interface CvdLedgerEntry {
  ant_id: string | null;
  bug_class: string | null;
  project: string | null;
  cve_ids: string[];
  ghsa_ids: string[];
  claude_severity: string | null;
  maintainer_severity: string | null;
  vendor_severity: string | null;
  vendor_confirmed: boolean;
  patched: boolean;
  patched_at: string | null;
  is_fixed: boolean;
  is_fixed_in_response: boolean;
  status: string | null;
  reveal_tier: string | null;
  revealed_at: string | null;
}

interface CvdPayload {
  as_of?: string;
  cve_records?: CvdRecord[];
  ghsa_records?: CvdRecord[];
  ledger?: CvdLedgerEntry[];
}

// ---------------------------------------------------------------------------
// bug_class -> CWE. The dashboard uses its own bug_class taxonomy (no CWE
// field), so we map it to a representative CWE, then route through the same
// CWE_TO_CATEGORY / agentRelevance logic sync-ghsa uses. Memory-safety classes
// map to non-agent CWEs on purpose so agentRelevance() drops them.
// ---------------------------------------------------------------------------

const BUG_CLASS_TO_CWE: Record<string, string> = {
  // --- agent-runtime relevant (kept by agentRelevance) ---
  rce: "CWE-94",
  "code-injection": "CWE-94",
  "command-injection": "CWE-77",
  "os-command-injection": "CWE-78",
  ssrf: "CWE-918",
  "path-traversal": "CWE-22",
  "directory-traversal": "CWE-22",
  "arbitrary-file-read": "CWE-22",
  "arbitrary-file-write": "CWE-22",
  "arbitrary-write": "CWE-22",
  "sql-injection": "CWE-89",
  xss: "CWE-79",
  "template-injection": "CWE-1336",
  deserialization: "CWE-502",
  "unsafe-deserialization": "CWE-502",
  xxe: "CWE-611",
  "broken-access-control": "CWE-863",
  "auth-bypass": "CWE-863",
  "authentication-bypass": "CWE-287",
  "privilege-escalation": "CWE-862",
  "confused-deputy": "CWE-863",
  "info-disclosure": "CWE-200",
  "information-disclosure": "CWE-200",
  "cors-misconfig": "CWE-942",
  "open-redirect": "CWE-601",
  // --- memory-safety / availability / crypto (dropped by agentRelevance) ---
  "heap-buffer-overflow": "CWE-122",
  "buffer-overflow": "CWE-120",
  "stack-buffer-overflow": "CWE-121",
  "use-after-free": "CWE-416",
  "double-free": "CWE-415",
  "integer-overflow": "CWE-190",
  "null-deref": "CWE-476",
  "out-of-bounds-read": "CWE-125",
  "out-of-bounds-write": "CWE-787",
  "crypto-failure": "CWE-327",
  "improper-cert-validation": "CWE-295",
  "signature-bypass": "CWE-347",
  "denial-of-service": "CWE-400",
};

// CWE -> ATR category (mirrors sync-ghsa.ts CWE_TO_CATEGORY; fallback model-abuse).
const CWE_TO_CATEGORY: Record<string, string> = {
  "CWE-94": "model-abuse",
  "CWE-78": "tool-poisoning",
  "CWE-77": "tool-poisoning",
  "CWE-89": "data-poisoning",
  "CWE-79": "context-exfiltration",
  "CWE-22": "context-exfiltration",
  "CWE-918": "tool-poisoning",
  "CWE-502": "model-abuse",
  "CWE-611": "context-exfiltration",
  "CWE-200": "context-exfiltration",
  "CWE-20": "prompt-injection",
  "CWE-863": "privilege-escalation",
  "CWE-862": "privilege-escalation",
  "CWE-287": "privilege-escalation",
  "CWE-601": "tool-poisoning",
  "CWE-1336": "prompt-injection",
};

function categoryForCwe(cwe: string | null): string {
  if (cwe && CWE_TO_CATEGORY[cwe]) return CWE_TO_CATEGORY[cwe];
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// ML-infra exclusion (same intent as sync-ghsa.ts AI_PACKAGES allowlist's
// inverse). The CVD source is general OSS, not a package feed, so we apply a
// project-name denylist of the ML-infra projects the contract enumerates.
// agentRelevance() is still the primary gate; this just short-circuits the
// known noise sources.
// ---------------------------------------------------------------------------

const ML_INFRA_DENYLIST_RX =
  /(?:^|[/@])(?:tensorflow|torch|pytorch|onnxruntime|gradio|mlflow|ray|diffusers|datasets|accelerate|huggingface[-_]?hub|transformers|vllm)(?:$|[/@.-])/i;

function isMlInfra(project: string): boolean {
  return ML_INFRA_DENYLIST_RX.test(project);
}

// ---------------------------------------------------------------------------
// Normalize a CVD record (+ findings) into a single advisory we triage.
// ---------------------------------------------------------------------------

interface CvdAdvisory {
  identifier: string; // CVE-... or GHSA-...
  cve_id: string | null;
  ghsa_id: string | null;
  projects: string[];
  bug_classes: string[];
  cwes: string[];
  severity: "critical" | "high" | "medium" | "low";
  title: string; // primary (longest) finding title
  advisory_body: string; // all finding titles joined, for provenance
  ant_ids: string[];
  revealed_at: string | null;
  // enrichment from ledger (best-effort)
  patched: boolean | null;
  patched_at: string | null;
  status: string | null;
  claude_severity: string | null;
  vendor_severity: string | null;
}

function normSeverity(s: string | null): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium" || v === "moderate") return "medium";
  if (v === "low") return "low";
  return "medium";
}

// Pick the strongest severity across findings (critical > high > medium > low).
function strongestSeverity(
  sevs: (string | null)[],
): "critical" | "high" | "medium" | "low" {
  const order = ["low", "medium", "high", "critical"];
  let best = -1;
  for (const s of sevs) {
    const idx = order.indexOf(normSeverity(s));
    if (idx > best) best = idx;
  }
  return (order[best] ?? "medium") as
    | "critical"
    | "high"
    | "medium"
    | "low";
}

function recordToAdvisory(
  rec: CvdRecord,
  ledgerByAnt: Map<string, CvdLedgerEntry>,
): CvdAdvisory | null {
  const findings = (rec.findings ?? []).filter(Boolean);
  const projects = Array.from(
    new Set(findings.map((f) => (f.project || "").trim()).filter(Boolean)),
  );
  const bugClasses = Array.from(
    new Set(findings.map((f) => (f.bug_class || "").trim()).filter(Boolean)),
  );
  const cwes = Array.from(
    new Set(
      bugClasses
        .map((b) => BUG_CLASS_TO_CWE[b])
        .filter((c): c is string => !!c),
    ),
  );
  const titles = findings
    .map((f) => (f.title || "").trim())
    .filter(Boolean);
  // Primary title = longest (most descriptive) finding title.
  const primaryTitle =
    titles.slice().sort((a, b) => b.length - a.length)[0] ||
    rec.identifier;
  const antIds = Array.from(
    new Set(findings.map((f) => f.ant_id || "").filter(Boolean)),
  );

  // Enrich from ledger by ant_id (first match wins).
  let led: CvdLedgerEntry | undefined;
  for (const a of antIds) {
    if (ledgerByAnt.has(a)) {
      led = ledgerByAnt.get(a);
      break;
    }
  }

  const identifier = (rec.identifier || "").trim();
  if (!identifier) return null;
  const isCve = /^CVE-/i.test(identifier);
  const isGhsa = /^GHSA-/i.test(identifier);

  const severity = strongestSeverity([
    ...findings.map((f) => f.severity),
    led?.claude_severity ?? null,
    led?.vendor_severity ?? null,
  ]);

  const advisoryBody = [
    `Anthropic CVD revealed finding(s) for ${identifier}.`,
    `Project(s): ${projects.join(", ") || "(unspecified)"}.`,
    `Bug class(es): ${bugClasses.join(", ") || "(unspecified)"}.`,
    "",
    "Finding titles:",
    ...titles.map((t) => `- ${t}`),
  ].join("\n");

  return {
    identifier,
    cve_id: isCve ? identifier.toUpperCase() : led?.cve_ids?.[0] ?? null,
    ghsa_id: isGhsa ? identifier : led?.ghsa_ids?.[0] ?? null,
    projects,
    bug_classes: bugClasses,
    cwes,
    severity,
    title: primaryTitle,
    advisory_body: advisoryBody,
    ant_ids: antIds,
    revealed_at: rec.revealed_at ?? led?.revealed_at ?? null,
    patched: led ? led.patched : null,
    patched_at: led?.patched_at ?? null,
    status: led?.status ?? null,
    claude_severity: led?.claude_severity ?? null,
    vendor_severity: led?.vendor_severity ?? null,
  };
}

// ---------------------------------------------------------------------------
// Fetch + parse payload.json.
// ---------------------------------------------------------------------------

async function fetchPayload(): Promise<
  | { ok: true; payload: CvdPayload }
  | { ok: false; reason: string }
> {
  let res: Response;
  try {
    res = await fetch(CVD_PAYLOAD_URL, {
      headers: { "User-Agent": POLITE_UA, Accept: "application/json" },
    });
  } catch (e) {
    // Network-level failure is fatal (exit 1), not a "no data path" case.
    throw new Error(`network error fetching ${CVD_PAYLOAD_URL}: ${e}`);
  }
  if (!res.ok) {
    return {
      ok: false,
      reason:
        `fetched ${CVD_PAYLOAD_URL} -> HTTP ${res.status} ${res.statusText}. ` +
        `The Anthropic CVD payload may have moved (new year path?) or been ` +
        `removed. Dashboard: ${CVD_DASHBOARD_URL}. Set ANTHROPIC_CVD_URL to ` +
        `point at the correct payload.json.`,
    };
  }
  const text = await res.text();
  let payload: CvdPayload;
  try {
    payload = JSON.parse(text) as CvdPayload;
  } catch (e) {
    return {
      ok: false,
      reason:
        `fetched ${CVD_PAYLOAD_URL} (HTTP 200, ${text.length} bytes) but it ` +
        `is not valid JSON: ${(e as Error).message}. The endpoint shape may ` +
        `have changed.`,
    };
  }
  const hasRecords =
    Array.isArray(payload.cve_records) || Array.isArray(payload.ghsa_records);
  if (!hasRecords) {
    return {
      ok: false,
      reason:
        `fetched ${CVD_PAYLOAD_URL} and parsed JSON, but neither ` +
        `cve_records nor ghsa_records is present. Schema changed; top-level ` +
        `keys: ${Object.keys(payload).join(", ")}.`,
    };
  }
  return { ok: true, payload };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE / GHSA ids and ANTHROPIC-CVD slugs across
// rules/ and proposals/ (same pattern as sync-huntr buildKnownIndex).
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
  ghsas: Set<string>;
  cvdIds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const ghsas = new Set<string>();
  const cvdIds = new Set<string>();
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
            ghsa?: string[];
            anthropic_cvd?: string[] | string;
          };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
      if (refs?.ghsa)
        for (const g of refs.ghsa) if (typeof g === "string") ghsas.add(g);
      if (refs?.anthropic_cvd) {
        const v = refs.anthropic_cvd;
        if (typeof v === "string") cvdIds.add(v);
        else if (Array.isArray(v))
          for (const x of v) if (typeof x === "string") cvdIds.add(x);
      }
      // Pick up ANTHROPIC-CVD-<slug> from filename too.
      const m = f.match(/ANTHROPIC-CVD-[a-z0-9-]+/i);
      if (m) cvdIds.add(m[0]);
    }
  }
  return { cves, ghsas, cvdIds };
}

// ---------------------------------------------------------------------------
// Detection-readiness: dashboard titles are prose, not payloads. We flag ready
// only if a finding title actually contains payload-like content.
// ---------------------------------------------------------------------------

const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "payload[:=]",
    "curl ",
    "POST /[a-z]",
    "GET /[a-z]",
    "<script>",
    "\\$\\(",
    "/etc/passwd",
    "\\.\\./\\.\\.",
    "' OR '1'='1",
  ].join("|"),
  "im",
);

function isDetectionReady(adv: CvdAdvisory): {
  ready: boolean;
  reason: string;
} {
  if (PAYLOAD_HEURISTICS_RX.test(adv.advisory_body))
    return { ready: true, reason: "payload-like content in finding title" };
  return {
    ready: false,
    reason:
      "Anthropic CVD finding is a prose description, no inline payload to " +
      "crystallize",
  };
}

// ---------------------------------------------------------------------------
// YAML helpers.
// ---------------------------------------------------------------------------

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50);
}

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

function jsonScalar(v: string | null): string {
  return v === null ? "null" : `"${v.replace(/"/g, '\\"')}"`;
}

// ---------------------------------------------------------------------------
// Proposal renderer (field order mirrors sync-huntr renderProposal).
// ---------------------------------------------------------------------------

function proposalId(adv: CvdAdvisory): string {
  if (adv.cve_id) return adv.cve_id;
  if (adv.ghsa_id) return adv.ghsa_id;
  const base = adv.projects[0] || adv.identifier;
  return `ANTHROPIC-CVD-${slugify(base + "-" + adv.identifier)}`;
}

function renderProposal(adv: CvdAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const pid = proposalId(adv);
  const category = categoryForCwe(adv.cwes[0] ?? null);
  const triage = isDetectionReady(adv);
  const responseActions =
    adv.severity === "critical" || adv.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = adv.cve_id ? `  cve:\n    - "${adv.cve_id}"\n` : "";
  const ghsaBlock = adv.ghsa_id ? `  ghsa:\n    - "${adv.ghsa_id}"\n` : "";
  const cweBlock =
    adv.cwes.length > 0
      ? `  cwe:\n${adv.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cvdBlock = `  anthropic_cvd:\n    - "${adv.identifier}"\n`;

  const title = adv.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = adv.advisory_body.replace(/\n+/g, " ").trim().slice(0, 600);
  const pkgNote = adv.projects.join(", ") || "unknown";
  const findingUrl = adv.ant_ids[0]
    ? `https://red.anthropic.com/2026/cvd/findings/${adv.ant_ids[0]}`
    : CVD_DASHBOARD_URL;

  // PoC excerpt comment — here it's the prose advisory body, embedded so the
  // human reviewer has the source text to convert into conditions if a payload
  // surfaces in the upstream advisory later.
  const bodyCommentLines = adv.advisory_body
    .split("\n")
    .filter((s) => s.trim().length > 0)
    .slice(0, 40)
    .map((s) => `    # ${s}`)
    .join("\n");

  return `# ATR rule proposal -- generated by scripts/sync-anthropic-cvd.ts
# Source: Anthropic Coordinated Vulnerability Disclosure (CVD) ledger
#         ${adv.ant_ids[0] ? findingUrl : CVD_DASHBOARD_URL}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The Anthropic CVD
#         dashboard publishes prose finding descriptions, not inline payloads,
#         so the advisory text is attached under detection.conditions as a
#         comment and under _anthropic_cvd_sync.advisory_body for triage.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${pid}
rule_version: 1
status: draft
description: >
  Anthropic CVD disclosed vulnerability${adv.cve_id ? ` (${adv.cve_id})` : adv.ghsa_id ? ` (${adv.ghsa_id})` : ""}.
  Affected: ${pkgNote}.
  ${desc}
author: "ATR Community (Anthropic CVD sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${adv.severity}

references:
${cveBlock}${ghsaBlock}${cweBlock}${cvdBlock}  external:
    - "${findingUrl}"
    - "${CVD_DASHBOARD_URL}"

metadata_provenance:
  anthropic_cvd: anthropic-cvd-sync
${adv.cve_id ? "  cve: anthropic-cvd-sync\n" : ""}${adv.ghsa_id ? "  ghsa: anthropic-cvd-sync\n" : ""}${adv.cwes.length ? "  cwe: anthropic-cvd-sync\n" : ""}
tags:
  category: ${category}
  subcategory: anthropic-cvd-imported
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
    # TODO(human): convert the Anthropic CVD advisory below into precision-safe
    # detection.conditions regex/string matchers. Without this work the rule
    # will neither fire nor be promotable to rules/.
    #
    # === Anthropic CVD advisory excerpt ===
${bodyCommentLines || "    # (no advisory body in source record)"}
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

# === sync-anthropic-cvd.ts provenance ===
_anthropic_cvd_sync:
  discovered_by: "Anthropic Claude CVD / Project Glasswing via sync-anthropic-cvd.ts"
  source: "${findingUrl}"
  dashboard: "${CVD_DASHBOARD_URL}"
  identifier: "${adv.identifier}"
  kind: ${adv.cve_id ? '"cve"' : adv.ghsa_id ? '"ghsa"' : '"finding"'}
  cve_id: ${jsonScalar(adv.cve_id)}
  ghsa_id: ${jsonScalar(adv.ghsa_id)}
  ant_ids: ${JSON.stringify(adv.ant_ids)}
  projects: ${JSON.stringify(adv.projects)}
  bug_classes: ${JSON.stringify(adv.bug_classes)}
  cwes: ${JSON.stringify(adv.cwes)}
  severity: "${adv.severity}"
  claude_severity: ${jsonScalar(adv.claude_severity)}
  vendor_severity: ${jsonScalar(adv.vendor_severity)}
  status: ${jsonScalar(adv.status)}
  patched: ${adv.patched === null ? "null" : adv.patched}
  patched_at: ${jsonScalar(adv.patched_at)}
  revealed_at: ${jsonScalar(adv.revealed_at)}
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(adv.advisory_body, "    ")}

# Triage flag read by promote-detection-ready.ts. Anthropic CVD records carry
# prose finding titles (not exploit payloads), so detection_ready is false
# unless a payload string is present inline. The generator lifts patterns from
# advisory_body only, never from a prose description.
_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  source_url: string;
  records_seen: number;
  ml_infra_excluded: number;
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
    source_url: CVD_PAYLOAD_URL,
    records_seen: 0,
    ml_infra_excluded: 0,
    filtered_not_agent: 0,
    skipped_existing: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-anthropic-cvd.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`source: ${CVD_PAYLOAD_URL}`);

  const fetched = await fetchPayload();
  if (!fetched.ok) {
    summary.errors.push(fetched.reason);
    console.error(`no data path: ${fetched.reason}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::anthropic-cvd-summary::${JSON.stringify({
        new_proposals: 0,
        records_seen: 0,
        source_url: CVD_PAYLOAD_URL,
        error: fetched.reason,
      })}`,
    );
    process.exit(2);
  }

  const payload = fetched.payload;
  const ledger = Array.isArray(payload.ledger) ? payload.ledger : [];
  const ledgerByAnt = new Map<string, CvdLedgerEntry>();
  for (const e of ledger) {
    if (e.ant_id) ledgerByAnt.set(e.ant_id, e);
  }

  const records: CvdRecord[] = [
    ...(payload.cve_records ?? []),
    ...(payload.ghsa_records ?? []),
  ];
  if (records.length === 0) {
    const reason =
      "payload.json parsed but cve_records and ghsa_records are both empty " +
      "(no revealed findings yet).";
    summary.errors.push(reason);
    console.error(`no data path: ${reason}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::anthropic-cvd-summary::${JSON.stringify({
        new_proposals: 0,
        records_seen: 0,
        source_url: CVD_PAYLOAD_URL,
        error: reason,
      })}`,
    );
    process.exit(2);
  }

  console.error(
    `fetched ${records.length} revealed records ` +
      `(${(payload.cve_records ?? []).length} CVE + ` +
      `${(payload.ghsa_records ?? []).length} GHSA), ` +
      `ledger=${ledger.length}`,
  );

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const rec of records) {
    if (writtenCount >= LIMIT) break;
    summary.records_seen += 1;

    const adv = recordToAdvisory(rec, ledgerByAnt);
    if (!adv) {
      summary.errors.push(`record with no identifier skipped`);
      continue;
    }

    // Gate 1: ML-infra exclusion.
    if (adv.projects.some((p) => isMlInfra(p))) {
      summary.ml_infra_excluded += 1;
      if (VERBOSE)
        console.error(
          `  skip (ml-infra) ${adv.identifier}: ${adv.projects.join(",")}`,
        );
      continue;
    }

    // Gate 2: agent-relevance (reuse sync-ghsa logic). Feed it CWEs + the
    // advisory text so a finding with no mapped CWE but agent-threat wording
    // still survives, and a memory-safety bug is dropped.
    const relevance = agentRelevance({
      summary: adv.title,
      description: adv.advisory_body,
      cwes: adv.cwes.map((c) => ({ cwe_id: c })),
    });
    if (!relevance.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(
          `  skip (not agent) ${adv.identifier} [${adv.bug_classes.join(",")}]: ${relevance.reason}`,
        );
      continue;
    }

    // Dedup: CVE id is the cross-source primary key, then GHSA, then CVD id.
    const pid = proposalId(adv);
    if (!FORCE) {
      if (adv.cve_id && known.cves.has(adv.cve_id)) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`  have-rule ${adv.cve_id}: already covered`);
        continue;
      }
      if (adv.ghsa_id && known.ghsas.has(adv.ghsa_id)) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`  have-rule ${adv.ghsa_id}: already covered`);
        continue;
      }
      if (known.cvdIds.has(adv.identifier) || known.cvdIds.has(pid)) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`  have-rule ${adv.identifier}: already covered`);
        continue;
      }
    }

    const outName = `${pid}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    const triage = isDetectionReady(adv);
    const body = renderProposal(adv);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}  [${relevance.reason}]`);
    } else {
      console.error(`  would write ${outName}  [${relevance.reason}]`);
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::anthropic-cvd-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      records_seen: summary.records_seen,
      ml_infra_excluded: summary.ml_infra_excluded,
      filtered_not_agent: summary.filtered_not_agent,
      skipped_existing: summary.skipped_existing,
      source_url: CVD_PAYLOAD_URL,
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
