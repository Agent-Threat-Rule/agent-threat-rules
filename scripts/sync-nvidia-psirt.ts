#!/usr/bin/env npx tsx
/**
 * sync-nvidia-psirt.ts
 *
 * Pulls NVIDIA PSIRT (Product Security Incident Response Team) security
 * bulletins for NVIDIA's AGENT-relevant AI products and emits ATR rule
 * proposals under proposals/nvidia-psirt/<CVE-or-bulletin-id>.proposal.yaml.
 *
 * REAL MACHINE-READABLE SOURCE (verified live 2026-06-12):
 *   GitHub repo `NVIDIA/product-security` (default branch `main`).
 *   Repo description: "Starting October 1, 2025, NVIDIA PSIRT will publish an
 *   initial set of security bulletins on GitHub in Markdown, CSAF, and CVE
 *   formats. Coverage will expand over time, while all bulletins remain
 *   available on the Product Security website."
 *
 *   Layout: <year>/<bulletin-id>/ — e.g. 2025/5726/. Each bulletin folder
 *   contains:
 *     - <bulletin-id>.json     CSAF 2.0 document (document.title,
 *                              document.tracking, vulnerabilities[] with
 *                              cve / cwe / notes / scores / references,
 *                              product_tree) — THE source we parse.
 *     - <bulletin-id>.md       human-readable markdown bulletin
 *     - CVE-XXXX-NNNNN.json    per-CVE CVE-record 5.x JSON
 *     - *.sha256               integrity sidecars (ignored)
 *
 *   We list the tree once via the GitHub git-trees API (recursive, like
 *   sync-huntr.ts lists protectai/ai-exploits) to find every <id>.json CSAF
 *   bulletin, then raw-fetch each from raw.githubusercontent.com. CVE detail
 *   (description / problemTypes) is read from the CSAF notes, which already
 *   mirror the CVE-record body; we do not need a second fetch per CVE.
 *
 *   If the repo ever disappears or stops shipping CSAF JSON, the script exits
 *   2 (recoverable) with a message naming exactly what was checked. We do NOT
 *   fall back to scraping nvidia.com/security (a JS-rendered portal with no
 *   machine-readable feed) — that path is documented as unavailable, not
 *   fabricated.
 *
 * SCOPE (ATR rule — do not widen):
 *   ATR detects AGENT-runtime threats (prompt injection, tool/MCP poisoning,
 *   context exfiltration, excessive autonomy). NVIDIA's catalogue is dominated
 *   by GPU display drivers, firmware, Jetson, CUDA, Omniverse, DGX, networking
 *   — none of which are agent-runtime threats. We keep ONLY bulletins whose
 *   product is an NVIDIA AI/agent product (NeMo / NeMo Agent Toolkit /
 *   Guardrails / Triton Inference Server / NIM / Riva / Merlin / BioNeMo /
 *   garak), then apply sync-ghsa.ts's agentRelevance() CWE/keyword gate as a
 *   second filter so a driver-style memory-safety CVE inside an AI product
 *   still gets dropped.
 *
 * Each proposal:
 *   - id: ATR-DRAFT-CVE-XXXX-NNNNN when CVE-assigned, else
 *     ATR-DRAFT-NVIDIA-PSIRT-<bulletin-id> for a bulletin without a per-CVE
 *     id (rare).
 *   - status=draft, maturity=experimental, detection.conditions empty (prose
 *     source — most PSIRT bulletins are descriptive, not payload-bearing).
 *   - _nvidia_psirt_sync.advisory_body holds the CSAF notes / description as
 *     provenance — the only payload source for promote-detection-ready.ts.
 *   - _triage.detection_ready almost always false (prose); true only if the
 *     notes carry payload-like content.
 *
 * Idempotency: dedup by CVE id AND by NVIDIA bulletin id against rules/ +
 * proposals/ (buildKnownIndex), unless --force.
 *
 * SECRET DISCIPLINE: GITHUB_TOKEN / GH_TOKEN are read from env ONLY (never a
 * --key arg, never echoed). Non-200 / timeout / rate-limit -> exit 2.
 *
 * Usage:
 *   npx tsx scripts/sync-nvidia-psirt.ts                 # dry-run
 *   npx tsx scripts/sync-nvidia-psirt.ts --write         # write proposals
 *   npx tsx scripts/sync-nvidia-psirt.ts --force         # overwrite existing
 *   npx tsx scripts/sync-nvidia-psirt.ts --verbose
 *   npx tsx scripts/sync-nvidia-psirt.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (schema mismatch, unexpected error)
 *   2 no data path available (recoverable: repo gone / rate limited / timeout)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "nvidia-psirt");

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

// env-only secret; never a CLI arg, never echoed.
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

// Network timeout (ms) — any hang counts as "no data path", exit 2.
const FETCH_TIMEOUT_MS = 20_000;

const NVIDIA_OWNER = "NVIDIA";
const NVIDIA_REPO = "product-security";
const NVIDIA_REF = "main";

// ---------------------------------------------------------------------------
// Scope: NVIDIA AI / agent products. The repo is dominated by GPU drivers,
// firmware, Jetson, CUDA, Omniverse, DGX, networking — all explicitly out of
// ATR scope. We keep ONLY bulletins whose title names an agent-relevant AI
// product. agentRelevance() (CWE/keyword gate, ported from sync-ghsa.ts) is
// the second filter applied to each individual CVE.
// ---------------------------------------------------------------------------

// Title-level allowlist (case-insensitive). Bounded tokens to avoid matching
// inside unrelated product names.
const AI_PRODUCT_RX =
  /\b(nemo|nemo[- ]?agent[- ]?toolkit|nemoclaw|guardrails?|nemo[- ]?guardrails|triton[- ]?inference[- ]?server|triton|\bnim\b|nvidia[- ]?inference[- ]?microservice|riva|merlin|transformers4rec|bionemo|garak|agent[- ]?toolkit)\b/i;

// Explicit out-of-scope product tokens (belt-and-suspenders: even if a future
// title accidentally also contains an AI token, these GPU/infra products are
// never agent-runtime threats). A title that hits an EXCLUDE token AND no AI
// token is dropped; a title hitting both is reported as ambiguous and skipped
// unless the AI token is NeMo/Triton/NIM-family.
const EXCLUDE_PRODUCT_RX =
  /\b(gpu display driver|geforce|shield|jetson|cuda toolkit|omniverse|dgx|data center gpu manager|\bdcgm\b|license system|gpu manager|firmware|cumulus|nvos|networking|snap4|nsight|mlnx|dpdk|vgpu|bluefield|connectx|holoscan|drive os|egx|base command|ucx|doca)\b/i;

// ---------------------------------------------------------------------------
// agentRelevance gate (ported from sync-ghsa.ts) — second filter per CVE.
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

// CWEs that map to an agent-runtime threat ATR can detect at the content
// layer. Deliberately NOT here: memory-safety / availability CWEs (the
// driver-style `CHECK fail` / overflow / OOB crashes).
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
  /code injection/,
  /command injection/,
  /deserializ/,
  /sql injection/,
  /path traversal/,
  /template injection/,
  /sandbox escape/,
  /exfiltrat/,
  /untrusted (input|data|manifest|model|content)/,
];

interface RelevanceInput {
  summary?: string;
  description?: string;
  cwes?: string[];
}

function agentRelevance(adv: RelevanceInput): {
  relevant: boolean;
  reason: string;
} {
  const cwes = adv.cwes ?? [];
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

// ---------------------------------------------------------------------------
// CSAF document shape (only the fields we read).
// ---------------------------------------------------------------------------

interface CsafNote {
  category?: string;
  title?: string;
  text?: string;
}
interface CsafScore {
  cvss_v4?: { baseSeverity?: string; baseScore?: number; vectorString?: string };
  cvss_v3?: { baseSeverity?: string; baseScore?: number; vectorString?: string };
}
interface CsafVulnerability {
  cve?: string;
  title?: string;
  cwe?: { id?: string; name?: string };
  notes?: CsafNote[];
  scores?: CsafScore[];
  references?: Array<{ url?: string; summary?: string; category?: string }>;
}
interface CsafDocument {
  document?: {
    title?: string;
    category?: string;
    tracking?: { id?: string; initial_release_date?: string };
    aggregate_severity?: { text?: string };
    references?: Array<{ url?: string; summary?: string; category?: string }>;
    publisher?: { name?: string };
  };
  product_tree?: unknown;
  vulnerabilities?: CsafVulnerability[];
}

// Normalized per-CVE advisory we render into a proposal.
interface PsirtAdvisory {
  cve_id: string | null;
  bulletin_id: string; // NVIDIA tracking id, e.g. "5726"
  bulletin_title: string;
  bulletin_url: string; // canonical NVIDIA bulletin URL
  product_name: string; // best-guess affected AI product
  title: string;
  description: string; // CSAF summary note (+ impacts)
  advisory_body: string; // full notes text concatenated (provenance payload)
  severity: "critical" | "high" | "medium" | "low";
  cwes: string[];
  cvss_score: number | null;
  cvss_metrics: string | null;
  references: string[];
  initial_release: string | null;
}

// ---------------------------------------------------------------------------
// Fetch helpers — env-only token, hard timeout, non-200 => caller treats as
// no-data (exit 2).
// ---------------------------------------------------------------------------

async function fetchWithTimeout(
  url: string,
  headers: Record<string, string>,
): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { headers, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

interface GhTreeEntry {
  path: string;
  type: "blob" | "tree";
}
interface GhTreeResponse {
  tree: GhTreeEntry[];
  truncated: boolean;
}

class NoDataError extends Error {}

async function listBulletinPaths(): Promise<string[]> {
  const u =
    `https://api.github.com/repos/${NVIDIA_OWNER}/${NVIDIA_REPO}` +
    `/git/trees/${NVIDIA_REF}?recursive=1`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": POLITE_UA,
  };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;

  let res: Response;
  try {
    res = await fetchWithTimeout(u, headers);
  } catch (e) {
    throw new NoDataError(
      `git-trees request failed/timed out for ${NVIDIA_OWNER}/${NVIDIA_REPO}: ${(e as Error).message}`,
    );
  }
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    throw new NoDataError(
      `git-trees rate limited (status ${res.status}, remaining=${remaining}, reset=${reset}). ` +
        `Set GITHUB_TOKEN in env to raise the limit.`,
    );
  }
  if (res.status === 404) {
    throw new NoDataError(
      `repo ${NVIDIA_OWNER}/${NVIDIA_REPO} not found (404). NVIDIA PSIRT GitHub ` +
        `bulletin repo moved or removed — re-verify the machine-readable source. ` +
        `Fallback nvidia.com/security has no machine-readable feed.`,
    );
  }
  if (!res.ok) {
    throw new NoDataError(
      `git-trees non-200: ${res.status} ${res.statusText} for ${u}`,
    );
  }
  const data = (await res.json()) as GhTreeResponse;
  if (data.truncated) {
    // ~2.2k entries today; truncation would mean we'd miss bulletins. Treat as
    // a partial/no-data condition rather than silently under-reporting.
    console.error(
      "warning: git-trees response was truncated — bulletin list is " +
        "incomplete. Consider per-year tree pagination.",
    );
  }
  // Keep only the CSAF document json (<year>/<id>/<id>.json), not CVE-*.json
  // or *.sha256.
  return data.tree
    .filter(
      (t) =>
        t.type === "blob" &&
        /^\d{4}\/\d+\/\d+\.json$/.test(t.path) &&
        !/\.sha256$/.test(t.path),
    )
    .map((t) => t.path)
    // newest year/bulletin first so --limit favours recent bulletins.
    .sort()
    .reverse();
}

async function fetchCsaf(path: string): Promise<CsafDocument> {
  const u =
    `https://raw.githubusercontent.com/${NVIDIA_OWNER}/${NVIDIA_REPO}/` +
    `${NVIDIA_REF}/${path}`;
  let res: Response;
  try {
    res = await fetchWithTimeout(u, { "User-Agent": POLITE_UA });
  } catch (e) {
    throw new NoDataError(
      `raw fetch failed/timed out for ${path}: ${(e as Error).message}`,
    );
  }
  if (res.status === 403 || res.status === 429) {
    throw new NoDataError(`raw fetch rate limited (${res.status}) for ${path}`);
  }
  if (!res.ok) {
    throw new Error(`raw fetch non-200: ${res.status} ${res.statusText} for ${path}`);
  }
  const text = await res.text();
  return JSON.parse(text) as CsafDocument;
}

// ---------------------------------------------------------------------------
// CSAF -> PsirtAdvisory[] (one per in-scope vulnerability).
// ---------------------------------------------------------------------------

function bulletinUrl(bulletinId: string): string {
  // NVIDIA canonical bulletin URL pattern.
  return `https://nvidia.custhelp.com/app/answers/detail/a_id/${bulletinId}`;
}

function normSeverity(s: string | undefined): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "medium";
}

function scoreSeverity(v: CsafVulnerability, docSeverity?: string): string {
  for (const s of v.scores ?? []) {
    const sev = s.cvss_v4?.baseSeverity ?? s.cvss_v3?.baseSeverity;
    if (sev) return sev;
  }
  return docSeverity ?? "medium";
}

function scoreNumber(v: CsafVulnerability): number | null {
  for (const s of v.scores ?? []) {
    const n = s.cvss_v4?.baseScore ?? s.cvss_v3?.baseScore;
    if (typeof n === "number") return n;
  }
  return null;
}

function scoreVector(v: CsafVulnerability): string | null {
  for (const s of v.scores ?? []) {
    const vec = s.cvss_v4?.vectorString ?? s.cvss_v3?.vectorString;
    if (vec) return vec;
  }
  return null;
}

function notesText(v: CsafVulnerability): { summary: string; full: string } {
  const parts: string[] = [];
  let summary = "";
  for (const n of v.notes ?? []) {
    const label = n.title || n.category || "note";
    const txt = (n.text ?? "").trim();
    if (!txt) continue;
    parts.push(`[${label}] ${txt}`);
    if (!summary && (n.category === "summary" || n.category === "description")) {
      summary = txt;
    }
  }
  if (!summary && parts.length) summary = (v.notes?.[0]?.text ?? "").trim();
  return { summary, full: parts.join("\n\n") };
}

function csafToAdvisories(
  doc: CsafDocument,
  bulletinIdFromPath: string,
): PsirtAdvisory[] {
  const d = doc.document ?? {};
  const bulletinTitle = (d.title ?? "").trim();
  const bulletinId = (d.tracking?.id ?? bulletinIdFromPath).toString().trim();
  const url = bulletinUrl(bulletinId);
  const docSeverity = d.aggregate_severity?.text;
  const initialRelease = d.tracking?.initial_release_date ?? null;
  // best-guess product name: strip the "Security Bulletin[:-] NVIDIA ... -
  // <Month Year>" wrapper.
  const product =
    bulletinTitle
      .replace(/^security bulletin\s*[:\-]\s*/i, "")
      .replace(/\s*[-–]\s*[A-Za-z]+\s+\d{4}\s*$/, "")
      .trim() || "NVIDIA AI product";

  const out: PsirtAdvisory[] = [];
  for (const v of doc.vulnerabilities ?? []) {
    const cwes = v.cwe?.id ? [v.cwe.id] : [];
    const { summary, full } = notesText(v);
    out.push({
      cve_id: v.cve ?? null,
      bulletin_id: bulletinId,
      bulletin_title: bulletinTitle,
      bulletin_url: url,
      product_name: product,
      title: (v.title || `${product} — ${v.cve ?? "vulnerability"}`).trim(),
      description: summary || full || bulletinTitle,
      advisory_body: full || summary || "(no notes provided in CSAF document)",
      severity: normSeverity(scoreSeverity(v, docSeverity)),
      cwes,
      cvss_score: scoreNumber(v),
      cvss_metrics: scoreVector(v),
      references: [
        url,
        ...(d.references ?? []).map((r) => r.url ?? "").filter(Boolean),
        ...(v.references ?? []).map((r) => r.url ?? "").filter(Boolean),
      ].filter((u, i, a) => u && a.indexOf(u) === i),
      initial_release: initialRelease,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE + NVIDIA bulletin ids across rules/ and
// proposals/.
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
  bulletins: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const bulletins = new Set<string>();
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
          references?: { cve?: string[]; nvidia_psirt?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.nvidia_psirt) {
        const v = refs.nvidia_psirt;
        if (typeof v === "string") bulletins.add(v);
        else if (Array.isArray(v))
          for (const b of v) if (typeof b === "string") bulletins.add(b);
      }
      // Provenance block bulletin_id, if present.
      const prov = (doc as { _nvidia_psirt_sync?: { bulletin_id?: string } })
        ?._nvidia_psirt_sync;
      if (prov?.bulletin_id) bulletins.add(String(prov.bulletin_id));
    }
  }
  return { cves, bulletins };
}

// ---------------------------------------------------------------------------
// Detection-readiness triage — PSIRT bulletins are almost always prose.
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
  ].join("|"),
  "im",
);

function isDetectionReady(a: PsirtAdvisory): { ready: boolean; reason: string } {
  if (PAYLOAD_HEURISTICS_RX.test(a.advisory_body))
    return { ready: true, reason: "payload-like content in advisory body" };
  return {
    ready: false,
    reason: "PSIRT bulletin is prose-only (no reproducer / payload section)",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer (aligned with sync-huntr / sync-ghsa schema).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see bulletin URL for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(a: PsirtAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = a.cve_id ?? `NVIDIA-PSIRT-${a.bulletin_id}`;
  const category = guessCategory(a.cwes);
  const triage = isDetectionReady(a);
  const responseActions =
    a.severity === "critical" || a.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = a.cve_id ? `  cve:\n    - "${a.cve_id}"\n` : "";
  const cweBlock =
    a.cwes.length > 0
      ? `  cwe:\n${a.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const psirtBlock = `  nvidia_psirt:\n    - "${a.bulletin_id}"\n`;
  const externalBlock = `  external:\n${a.references
    .map((u) => `    - "${u}"`)
    .join("\n")}\n`;

  const title = a.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = a.description.replace(/\n+/g, " ").trim();

  // Embed advisory body as YAML comment lines in detection.conditions so the
  // human reviewer has the source text without re-fetching.
  const bodyCommentLines =
    a.advisory_body
      .split("\n")
      .filter((s) => s.trim().length > 0)
      .slice(0, 60)
      .map((s) => `    # ${s}`)
      .join("\n") || "    # (no advisory body in CSAF document)";

  return `# ATR rule proposal -- generated by scripts/sync-nvidia-psirt.ts
# Source: NVIDIA PSIRT security bulletin ${a.bulletin_id} (CSAF) via NVIDIA/product-security
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The PSIRT advisory
#         body is attached as a YAML comment under detection.conditions and in
#         _nvidia_psirt_sync.advisory_body for conversion to a regex.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  NVIDIA PSIRT security bulletin ${a.bulletin_id}${a.cve_id ? ` (${a.cve_id})` : ""}.
  Affected NVIDIA AI product: ${a.product_name}.
  ${desc.slice(0, 600)}
author: "ATR Community (NVIDIA PSIRT sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${a.severity}

references:
${cveBlock}${cweBlock}${psirtBlock}${externalBlock}
metadata_provenance:
  nvidia_psirt: nvidia-psirt-sync
${a.cve_id ? "  cve: nvidia-psirt-sync\n" : ""}${a.cwes.length ? "  cwe: nvidia-psirt-sync\n" : ""}
tags:
  category: ${category}
  subcategory: nvidia-psirt-imported
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
    # TODO(human): convert the NVIDIA PSIRT advisory below into precision-safe
    # detection.conditions regex/string matchers. Without this work the rule
    # will neither fire nor be promotable to rules/.
    #
    # === PSIRT advisory body (from NVIDIA/product-security CSAF) ===
${bodyCommentLines}
    []

response:
  actions:
${responseActions.map((x) => `    - ${x}`).join("\n")}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"

# === sync-nvidia-psirt.ts provenance ===
_nvidia_psirt_sync:
  bulletin_id: "${a.bulletin_id}"
  bulletin_title: "${a.bulletin_title.replace(/"/g, '\\"')}"
  product_name: "${a.product_name.replace(/"/g, '\\"')}"
  cve_id: ${a.cve_id ? `"${a.cve_id}"` : "null"}
  cwe: ${JSON.stringify(a.cwes)}
  severity: "${a.severity}"
  cvss_score: ${a.cvss_score ?? "null"}
  cvss_metrics: ${a.cvss_metrics ? `"${a.cvss_metrics.replace(/"/g, '\\"')}"` : "null"}
  initial_release: ${a.initial_release ? `"${a.initial_release}"` : "null"}
  bulletin_url: "${a.bulletin_url}"
  imported_at: "${new Date().toISOString()}"
  data_source_used: "NVIDIA/product-security CSAF (git-trees + raw)"
  advisory_body: |
${indentForLiteralBlock(a.advisory_body, "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  bulletins_listed: number;
  bulletins_in_scope_product: number;
  bulletins_out_of_scope_product: number;
  vulns_seen: number;
  vulns_filtered_not_agent: number;
  vulns_already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  fetch_failures: number;
  errors: string[];
  written_files: string[];
}

function printSummaryAndExit(summary: RunSummary, code: number): never {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::nvidia-psirt-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      bulletins_in_scope_product: summary.bulletins_in_scope_product,
      vulns_filtered_not_agent: summary.vulns_filtered_not_agent,
      vulns_seen: summary.vulns_seen,
      fetch_failures: summary.fetch_failures,
    })}`,
  );
  process.exit(code);
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    bulletins_listed: 0,
    bulletins_in_scope_product: 0,
    bulletins_out_of_scope_product: 0,
    vulns_seen: 0,
    vulns_filtered_not_agent: 0,
    vulns_already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    fetch_failures: 0,
    errors: [],
    written_files: [],
  };

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  console.error("=== sync-nvidia-psirt.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`source: github.com/${NVIDIA_OWNER}/${NVIDIA_REPO}@${NVIDIA_REF} (CSAF)`);
  if (!TOKEN && VERBOSE)
    console.error(
      "note: no GITHUB_TOKEN/GH_TOKEN in env — using the 60 req/hr " +
        "unauthenticated GitHub API limit; will exit 2 if rate limited.",
    );

  // --- list bulletins via git-trees ---
  let paths: string[];
  try {
    paths = await listBulletinPaths();
  } catch (e) {
    if (e instanceof NoDataError) {
      summary.errors.push(`NO DATA PATH: ${e.message}`);
      console.error(`no data path: ${e.message}`);
      printSummaryAndExit(summary, 2);
    }
    throw e;
  }
  summary.bulletins_listed = paths.length;
  console.error(`listed ${paths.length} CSAF bulletins`);

  const known = buildKnownIndex();
  const seenCveOrId = new Set<string>();
  let writtenCount = 0;

  for (const path of paths) {
    if (writtenCount >= LIMIT) break;
    const bulletinIdFromPath = path.split("/")[1] ?? path;

    // We must fetch the CSAF to know the product title authoritatively, but
    // we can pre-filter cheaply: the directory tells us nothing about product,
    // so fetch then scope-check.
    let doc: CsafDocument;
    try {
      doc = await fetchCsaf(path);
    } catch (e) {
      if (e instanceof NoDataError) {
        // network/rate-limit mid-run -> recoverable, exit 2.
        summary.errors.push(`NO DATA PATH: ${e.message}`);
        console.error(`no data path mid-run: ${e.message}`);
        printSummaryAndExit(summary, 2);
      }
      summary.fetch_failures += 1;
      if (VERBOSE) console.error(`  fetch/parse fail ${path}: ${(e as Error).message}`);
      continue;
    }

    const bulletinTitle = doc.document?.title ?? "";

    // --- scope gate 1: AI/agent product allowlist on the bulletin title ---
    const isAiProduct =
      AI_PRODUCT_RX.test(bulletinTitle) &&
      !(EXCLUDE_PRODUCT_RX.test(bulletinTitle) && !/\b(nemo|triton|\bnim\b|riva|merlin|bionemo|garak)\b/i.test(bulletinTitle));
    if (!isAiProduct) {
      summary.bulletins_out_of_scope_product += 1;
      if (VERBOSE)
        console.error(`  skip (not AI product): ${bulletinTitle || path}`);
      continue;
    }
    summary.bulletins_in_scope_product += 1;
    if (VERBOSE) console.error(`AI product: ${bulletinTitle}`);

    const advisories = csafToAdvisories(doc, bulletinIdFromPath);
    for (const a of advisories) {
      if (writtenCount >= LIMIT) break;
      summary.vulns_seen += 1;

      // --- scope gate 2: per-CVE agent-relevance (CWE/keyword) ---
      const rel = agentRelevance({
        summary: a.title,
        description: a.advisory_body,
        cwes: a.cwes,
      });
      if (!rel.relevant) {
        summary.vulns_filtered_not_agent += 1;
        if (VERBOSE)
          console.error(`    skip (not agent) ${a.cve_id ?? a.bulletin_id}: ${rel.reason}`);
        continue;
      }

      // dedup key: CVE id is primary cross-source key; fall back to bulletin id.
      const dedupeKey = a.cve_id ?? `NVIDIA-PSIRT-${a.bulletin_id}`;
      if (seenCveOrId.has(dedupeKey)) continue;
      seenCveOrId.add(dedupeKey);

      if (!FORCE && a.cve_id && known.cves.has(a.cve_id)) {
        summary.vulns_already_known += 1;
        if (VERBOSE) console.error(`    have-rule ${a.cve_id}: already covered`);
        continue;
      }
      if (!FORCE && !a.cve_id && known.bulletins.has(a.bulletin_id)) {
        summary.vulns_already_known += 1;
        continue;
      }

      const outName = `${dedupeKey}.proposal.yaml`;
      const outPath = join(PROPOSALS_DIR, outName);
      if (existsSync(outPath) && !FORCE) {
        summary.vulns_already_known += 1;
        if (VERBOSE) console.error(`    have-proposal ${outName}`);
        continue;
      }

      const body = renderProposal(a);
      const triage = isDetectionReady(a);
      if (WRITE) {
        writeFileSync(outPath, body, "utf-8");
        summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
        console.error(`    wrote ${outName}`);
      } else {
        console.error(`    would write ${outName}`);
      }
      summary.new_proposals += 1;
      if (triage.ready) summary.new_detection_ready += 1;
      else summary.new_tracking_only += 1;
      writtenCount += 1;
    }
  }

  printSummaryAndExit(summary, 0);
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}

export { agentRelevance, csafToAdvisories, AI_PRODUCT_RX, EXCLUDE_PRODUCT_RX };
