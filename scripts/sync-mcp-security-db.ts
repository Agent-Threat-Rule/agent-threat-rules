#!/usr/bin/env npx tsx
/**
 * sync-mcp-security-db.ts
 *
 * Pulls the Cloud Security Alliance community MCP vulnerability database
 * (ModelContextProtocol-Security/vulnerability-db) and emits ATR rule
 * proposals under proposals/mcp-security-db/<CVE-or-MCPS-id>.proposal.yaml.
 *
 * Source: https://github.com/ModelContextProtocol-Security/vulnerability-db
 *
 * Why this source: it is a 100% MCP-specific, OSV-schema vulnerability feed
 * curated by the CSA MCP-Security community. Every entry is, by construction,
 * an agent-runtime / MCP threat — so unlike sync-ghsa.ts there is NO AI-package
 * allowlist and NO agentRelevance second gate. All entries are in scope.
 *
 * REAL data layout (verified against the live repo on 2026-06-12 — the task
 * brief's assumed path was close but not exact, so this was crawled, not
 * assumed):
 *   - Default branch: main
 *   - Advisories live at:  advisories/YYYY/MM/DD/OSV-MCPS-YYYY-<8HEX>-osv.json
 *     (the on-disk id is prefixed `OSV-MCPS-`, not `MCPS-`; the path date dirs
 *      are the publish date; the filename is `<id>-osv.json`.)
 *   - Each file is a single OSV record (schema_version 1.6.x).
 *   - OSV fields actually present:
 *       id            -> "OSV-MCPS-YYYY-<8HEX>"
 *       aliases[]     -> may contain CVE-* (optional; absent in early records)
 *       summary       -> one-line title
 *       details       -> markdown body (the advisory_body payload source)
 *       severity[]    -> [{ type: "CVSS_V3", score: "CVSS:3.1/..." }]
 *       affected[]    -> [{ package:{ecosystem,name}, ranges:[...] }]
 *       references[]  -> [{ type, url }]  (CVE may appear in an ADVISORY url)
 *       database_specific:
 *         cwe_ids[]            -> ["CWE-200", ...]
 *         severity_assessment  -> "High - ..." (free text, leads with a word)
 *         impact / mitigations
 *         mcps_metadata:
 *           discovery_method / reproduction_steps / evidence / fix_validation
 *           (reproduction_steps is the richest PoC source — often a numbered
 *            repro that makes the entry detection_ready.)
 *
 * Crawl approach (mirrors sync-huntr.ts's ai-exploits crawl):
 *   1. GitHub git trees API (recursive) to list every advisory blob:
 *      api.github.com/repos/.../git/trees/<default-branch>?recursive=1
 *      (GITHUB_TOKEN used if present to lift the 60/hr unauth limit).
 *   2. Fetch each via raw.githubusercontent.com.
 * The UUIDv7-style path is time-ordered so a daily run could diff by date dir;
 * for this backfill we crawl all and rely on buildKnownIndex for idempotency.
 *
 * Detection-readiness triage (same contract as sync-ghsa.ts):
 *   detection_ready=true when the OSV `details` body OR the mcps_metadata
 *   reproduction_steps contains payload-like content (fenced code block, a
 *   "Proof of Concept" / "Reproduce" header, an explicit payload/command, a
 *   numbered repro). Prose-only entries are tracking-only (false).
 *
 * Auth:
 *   GITHUB_TOKEN / GH_TOKEN env var optional (env-only, never a --key arg,
 *   never echoed). Without it the run uses the 60-req/hour unauthenticated
 *   limit; on rate-limit it exits 2 (recoverable).
 *
 * Usage:
 *   npx tsx scripts/sync-mcp-security-db.ts                 # dry-run
 *   npx tsx scripts/sync-mcp-security-db.ts --write         # write proposals
 *   npx tsx scripts/sync-mcp-security-db.ts --force         # overwrite existing
 *   npx tsx scripts/sync-mcp-security-db.ts --verbose
 *   npx tsx scripts/sync-mcp-security-db.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network / schema mismatch)
 *   2 no data path available (repo or advisories dir not found, or rate
 *     limited) — recoverable; a daily cron retries.
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "mcp-security-db");

const SOURCE_OWNER = "ModelContextProtocol-Security";
const SOURCE_REPO = "vulnerability-db";
// Verified default branch (2026-06-12). The trees call uses this ref; if the
// repo ever renames its default branch the call 404s and we exit 2.
const SOURCE_REF = "main";
const SOURCE_REPO_URL = `https://github.com/${SOURCE_OWNER}/${SOURCE_REPO}`;

const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

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

// Env-only GitHub token. NEVER accept a --key arg, NEVER echo the value.
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

// Match the advisory blob path: advisories/YYYY/MM/DD/OSV-MCPS-...-osv.json.
// Kept permissive on the id body so a future id format (e.g. UUIDv7) still
// matches as long as it ends in -osv.json under advisories/.
const ADVISORY_PATH_RX =
  /^advisories\/.*\/OSV-MCPS-[^/]+-osv\.json$/i;
// Fallback: any *-osv.json under advisories/ (in case the OSV-MCPS- prefix
// convention changes but the -osv.json suffix stays).
const ADVISORY_PATH_FALLBACK_RX = /^advisories\/.*-osv\.json$/i;

// ---------------------------------------------------------------------------
// OSV record types (only the fields we read).
// ---------------------------------------------------------------------------

interface OsvSeverity {
  type?: string;
  score?: string;
}
interface OsvPackage {
  ecosystem?: string;
  name?: string;
}
interface OsvAffected {
  package?: OsvPackage;
  ranges?: unknown;
  versions?: string[];
}
interface OsvReference {
  type?: string;
  url?: string;
}
interface McpsMetadata {
  discovery_method?: string;
  reproduction_steps?: string;
  evidence?: string;
  fix_validation?: string;
}
interface OsvDatabaseSpecific {
  cwe_ids?: string[];
  severity_assessment?: string;
  impact?: string;
  mitigations?: string[];
  mcps_metadata?: McpsMetadata;
  // Some OSV producers nest severity/cwe directly; handle defensively.
  severity?: string;
  cwe?: string | string[];
}
interface OsvRecord {
  schema_version?: string;
  id?: string;
  modified?: string;
  published?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: OsvDatabaseSpecific;
}

// Normalized shape used by the renderer.
interface Advisory {
  mcps_id: string; // OSV-MCPS-YYYY-XXXXXXXX
  cve_id: string | null; // first CVE alias / reference, if any
  cve_aliases: string[]; // all CVE-* found
  title: string;
  details: string; // OSV markdown body -> advisory_body
  severity: "critical" | "high" | "medium" | "low";
  cwes: string[];
  affected: string[]; // "ecosystem:name"
  references: string[]; // all reference URLs
  cvss_vectors: string[];
  metadata: McpsMetadata;
  impact: string | null;
  mitigations: string[];
  published: string | null;
  source_url: string; // GitHub advisory file URL
}

// ---------------------------------------------------------------------------
// CWE -> ATR category. Mirrors sync-ghsa.ts; fallback per contract is
// "tool-poisoning" (this source is 100% MCP tool-layer), then text detect.
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
  "CWE-922": "context-exfiltration",
  "CWE-20": "prompt-injection",
  "CWE-863": "privilege-escalation",
  "CWE-862": "privilege-escalation",
  "CWE-601": "tool-poisoning",
  "CWE-1336": "prompt-injection",
};

// Text-signal detection when no mapped CWE is present. MCP entries default to
// tool-poisoning, but prompt-injection / context-exfiltration are common and
// detectable from the summary/details wording (per the task brief).
function categoryForAdvisory(a: Advisory): string {
  for (const c of a.cwes) {
    if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  }
  const haystack =
    `${a.title} ${a.details} ${a.impact ?? ""}`.toLowerCase();
  if (/prompt[- ]injection|jailbreak|system prompt|indirect injection/.test(haystack))
    return "prompt-injection";
  if (
    /exfiltrat|data (?:leak|disclos)|credential (?:expos|leak)|info(?:rmation)?[- ](?:leak|disclos)|secret(?:s)? (?:expos|leak)|read .*\.env|sensitive (?:file|data|info)/.test(
      haystack,
    )
  )
    return "context-exfiltration";
  if (/ssrf|server[- ]side[- ]request[- ]forgery/.test(haystack))
    return "context-exfiltration";
  if (/path[- ]traversal|lfi|local[- ]file/.test(haystack))
    return "context-exfiltration";
  if (
    /auth(?:entication)?[- ]bypass|unauthor(?:i[sz]ed|ised)|privilege[- ]escalat/.test(
      haystack,
    )
  )
    return "privilege-escalation";
  if (
    /tool poisoning|malicious tool|tool description|rug[- ]?pull|\brce\b|remote code|command injection|arbitrary code|deserial/.test(
      haystack,
    )
  )
    return "tool-poisoning";
  // 100% MCP source -> tool-poisoning default (per contract).
  return "tool-poisoning";
}

// ---------------------------------------------------------------------------
// Severity derivation. The OSV records here carry severity in two forms:
//   1) database_specific.severity_assessment -> "High - ..." (leads with word)
//   2) severity[].score -> CVSS vector "CVSS:3.1/.../C:H/I:N/A:N"
// We prefer (1) when it leads with a known word, else estimate from the CVSS
// vector base metrics, else default medium.
// ---------------------------------------------------------------------------

type Sev = "critical" | "high" | "medium" | "low";

function normalizeSevWord(s: string | undefined): Sev | null {
  const v = (s || "").trim().toLowerCase();
  if (v.startsWith("critical")) return "critical";
  if (v.startsWith("high")) return "high";
  if (v.startsWith("medium") || v.startsWith("moderate")) return "medium";
  if (v.startsWith("low")) return "low";
  return null;
}

// Coarse CVSS-vector -> severity bucket. We do NOT compute the exact CVSS base
// score (no full formula); instead we bucket on the high-impact metrics, which
// is sufficient to pick response.actions. Conservative: unknown -> medium.
function sevFromCvssVector(vec: string | undefined): Sev | null {
  if (!vec) return null;
  const v = vec.toUpperCase();
  const conf = /\bC:H\b/.test(v);
  const integ = /\bI:H\b/.test(v);
  const avail = /\bA:H\b/.test(v);
  const netAv = /\bAV:N\b/.test(v);
  const lowAc = /\bAC:L\b/.test(v);
  const noPriv = /\bPR:N\b/.test(v);
  const noUi = /\bUI:N\b/.test(v);
  const highImpactCount = [conf, integ, avail].filter(Boolean).length;
  if (highImpactCount >= 2 && netAv && lowAc && noPriv) return "critical";
  if (highImpactCount >= 1 && netAv && (noPriv || noUi)) return "high";
  if (highImpactCount >= 1) return "medium";
  return "low";
}

function deriveSeverity(rec: OsvRecord): Sev {
  const ds = rec.database_specific ?? {};
  const fromAssessment = normalizeSevWord(ds.severity_assessment);
  if (fromAssessment) return fromAssessment;
  const fromDsSeverity = normalizeSevWord(ds.severity);
  if (fromDsSeverity) return fromDsSeverity;
  const vec = (rec.severity ?? [])
    .map((s) => s.score)
    .find((s) => typeof s === "string" && /^CVSS/i.test(s));
  const fromCvss = sevFromCvssVector(vec);
  if (fromCvss) return fromCvss;
  return "medium";
}

// ---------------------------------------------------------------------------
// CVE harvesting: from aliases[] and from any reference URL containing a CVE.
// ---------------------------------------------------------------------------

const CVE_RX = /CVE-\d{4}-\d{4,}/gi;

function harvestCves(rec: OsvRecord): string[] {
  const out = new Set<string>();
  for (const a of rec.aliases ?? []) {
    if (typeof a !== "string") continue;
    const m = a.match(CVE_RX);
    if (m) for (const c of m) out.add(c.toUpperCase());
  }
  for (const r of rec.references ?? []) {
    if (typeof r?.url !== "string") continue;
    const m = r.url.match(CVE_RX);
    if (m) for (const c of m) out.add(c.toUpperCase());
  }
  return [...out];
}

function normalizeCwes(rec: OsvRecord): string[] {
  const ds = rec.database_specific ?? {};
  const out = new Set<string>();
  for (const c of ds.cwe_ids ?? []) {
    if (typeof c === "string" && /^CWE-\d+/i.test(c.trim()))
      out.add(c.trim().toUpperCase().split(/\s|#/)[0]);
  }
  if (typeof ds.cwe === "string" && /^CWE-\d+/i.test(ds.cwe.trim()))
    out.add(ds.cwe.trim().toUpperCase().split(/\s|#/)[0]);
  if (Array.isArray(ds.cwe))
    for (const c of ds.cwe)
      if (typeof c === "string" && /^CWE-\d+/i.test(c.trim()))
        out.add(c.trim().toUpperCase().split(/\s|#/)[0]);
  return [...out];
}

// ---------------------------------------------------------------------------
// Detection readiness: payload-like content in details OR reproduction_steps.
// (Same intent as sync-ghsa.ts isDetectionReady; tuned for this source's
// numbered-repro style which has no code fences but is still an attack input.)
// ---------------------------------------------------------------------------

const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```", // fenced code block
    "## *Proof of Concept",
    "## *Reproduc", // Reproducer / Reproduction
    "## *Exploit",
    "## *PoC",
    "\\bpayload\\b",
    "\\bcurl \\b",
    "POST \\/[a-z]",
    "GET \\/[a-z]",
    "<script>",
    "\\$\\s*[a-z]", // shell prompt
    "\\bnpx?\\b .*--",
  ].join("|"),
  "im",
);

// A numbered repro list ("1. ... 2. ...") with 2+ steps is treated as
// extractable attack input even without code fences.
const NUMBERED_REPRO_RX = /(^|\n)\s*1[.)]\s+\S+[\s\S]*?(^|\n)\s*2[.)]\s+\S+/m;

function isDetectionReady(a: Advisory): { ready: boolean; reason: string } {
  const repro = a.metadata.reproduction_steps ?? "";
  const body = `${a.details}\n${repro}\n${a.metadata.evidence ?? ""}`;
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return { ready: true, reason: "payload-like content in advisory body / PoC" };
  if (NUMBERED_REPRO_RX.test(repro) || NUMBERED_REPRO_RX.test(a.details))
    return { ready: true, reason: "numbered reproduction steps present" };
  if (a.references.some((r) => /poc|exploit-db|exploit|reddit\.com|youtu/i.test(r)))
    return { ready: true, reason: "PoC / report reference link present" };
  return {
    ready: false,
    reason: "prose-only advisory; no extractable payload or reproduction",
  };
}

// ---------------------------------------------------------------------------
// GitHub tree crawl.
// ---------------------------------------------------------------------------

interface GhTreeEntry {
  path: string;
  type: "blob" | "tree";
  sha: string;
}
interface GhTreeResponse {
  sha: string;
  tree: GhTreeEntry[];
  truncated: boolean;
  message?: string;
}

async function listAdvisoryPaths(): Promise<
  { paths: string[]; rateLimited: boolean; notFound: boolean }
> {
  const u =
    `https://api.github.com/repos/${SOURCE_OWNER}/${SOURCE_REPO}` +
    `/git/trees/${SOURCE_REF}?recursive=1`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": POLITE_UA,
  };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;

  const res = await fetch(u, { headers });
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    console.error(
      `rate limited on git trees: remaining=${remaining}, reset=${reset}. ` +
        "Set GITHUB_TOKEN to raise the limit.",
    );
    return { paths: [], rateLimited: true, notFound: false };
  }
  if (res.status === 404) {
    console.error(
      `repo/ref not found: ${SOURCE_OWNER}/${SOURCE_REPO}@${SOURCE_REF}. ` +
        "The default branch may have been renamed.",
    );
    return { paths: [], rateLimited: false, notFound: true };
  }
  if (!res.ok) {
    throw new Error(
      `git trees fetch failed: ${res.status} ${res.statusText}`,
    );
  }
  const data = (await res.json()) as GhTreeResponse;
  if (data.truncated) {
    // The tree is small today (single-digit advisories). If the DB grows past
    // the 100k-entry / 7MB trees-API cap, paginate per year subdir instead.
    console.error(
      "warning: git trees response truncated -- paginate per advisories/<year> subtree.",
    );
  }
  let paths = data.tree
    .filter((t) => t.type === "blob" && ADVISORY_PATH_RX.test(t.path))
    .map((t) => t.path);
  if (paths.length === 0) {
    // Path convention may have shifted; fall back to any *-osv.json under
    // advisories/ before giving up.
    paths = data.tree
      .filter((t) => t.type === "blob" && ADVISORY_PATH_FALLBACK_RX.test(t.path))
      .map((t) => t.path);
    if (paths.length > 0 && VERBOSE)
      console.error(
        `note: matched ${paths.length} advisories via fallback path pattern.`,
      );
  }
  return { paths, rateLimited: false, notFound: false };
}

async function fetchAdvisoryFile(path: string): Promise<string> {
  const u =
    `https://raw.githubusercontent.com/${SOURCE_OWNER}/${SOURCE_REPO}/` +
    `${SOURCE_REF}/${path}`;
  const res = await fetch(u, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok)
    throw new Error(
      `raw fetch failed for ${path}: ${res.status} ${res.statusText}`,
    );
  return await res.text();
}

function githubFileUrl(path: string): string {
  return `${SOURCE_REPO_URL}/blob/${SOURCE_REF}/${path}`;
}

// ---------------------------------------------------------------------------
// OSV record -> Advisory.
// ---------------------------------------------------------------------------

function recordToAdvisory(
  path: string,
  raw: string,
): Advisory | { error: string } {
  let rec: OsvRecord;
  try {
    rec = JSON.parse(raw) as OsvRecord;
  } catch (e) {
    return { error: `json parse failed for ${path}: ${(e as Error).message}` };
  }
  if (!rec || typeof rec !== "object")
    return { error: `non-object OSV record in ${path}` };
  const mcpsId = (rec.id || "").trim();
  if (!mcpsId) return { error: `no id in ${path}` };

  const cveAliases = harvestCves(rec);
  const cwes = normalizeCwes(rec);
  const affected = (rec.affected ?? [])
    .map((a) => {
      const eco = a.package?.ecosystem ?? "";
      const name = a.package?.name ?? "";
      return eco || name ? `${eco}:${name}` : "";
    })
    .filter(Boolean);
  const references = (rec.references ?? [])
    .map((r) => (typeof r?.url === "string" ? r.url : ""))
    .filter(Boolean);
  const cvssVectors = (rec.severity ?? [])
    .map((s) => s.score)
    .filter((s): s is string => typeof s === "string" && /^CVSS/i.test(s));
  const ds = rec.database_specific ?? {};

  return {
    mcps_id: mcpsId,
    cve_id: cveAliases[0] ?? null,
    cve_aliases: cveAliases,
    title: (rec.summary || mcpsId).trim(),
    details: (rec.details || "").trim(),
    severity: deriveSeverity(rec),
    cwes,
    affected,
    references,
    cvss_vectors: cvssVectors,
    metadata: ds.mcps_metadata ?? {},
    impact: ds.impact ?? null,
    mitigations: Array.isArray(ds.mitigations) ? ds.mitigations : [],
    published: rec.published ?? null,
    source_url: githubFileUrl(path),
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE / MCPS ids across rules/ and proposals/.
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
  mcps: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const mcps = new Set<string>();
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
            cve?: string[] | string;
            mcps_id?: string[] | string;
          };
        }
      )?.references;
      if (refs?.cve) {
        const v = refs.cve;
        if (typeof v === "string") cves.add(v.toUpperCase());
        else if (Array.isArray(v))
          for (const c of v)
            if (typeof c === "string") cves.add(c.toUpperCase());
      }
      if (refs?.mcps_id) {
        const v = refs.mcps_id;
        if (typeof v === "string") mcps.add(v);
        else if (Array.isArray(v))
          for (const m of v) if (typeof m === "string") mcps.add(m);
      }
      // Also harvest MCPS id from filename (OSV-MCPS-...).
      const fm = f.match(/OSV-MCPS-[0-9]{4}-[A-Z0-9]+/i);
      if (fm) mcps.add(fm[0]);
    }
  }
  return { cves, mcps };
}

// ---------------------------------------------------------------------------
// YAML literal-block helper (shared idea with sync-ghsa.ts).
// ---------------------------------------------------------------------------

const BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > BODY_MAX_CHARS
      ? text.slice(0, BODY_MAX_CHARS) +
        `\n\n... (truncated at ${BODY_MAX_CHARS} chars; see source_url for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

// PoC excerpt as YAML comment lines under detection.conditions.
function pocCommentLines(a: Advisory): string {
  const repro = a.metadata.reproduction_steps?.trim();
  const src = repro && repro.length > 0 ? repro : a.details;
  const lines = (src || "")
    .split("\n")
    .filter((s) => s.trim().length > 0)
    .slice(0, 60)
    .map((s) => `    # ${s}`);
  return lines.length > 0
    ? lines.join("\n")
    : "    # (no reproduction / payload text in source advisory)";
}

function tpBlock(a: Advisory): string {
  const repro = a.metadata.reproduction_steps?.trim();
  if (!repro || repro.length === 0) return `  true_positives: []\n`;
  const body = repro
    .split("\n")
    .slice(0, 30)
    .map((s) => `        ${s}`)
    .join("\n");
  return `  true_positives:\n    - name: "MCP advisory reproduction excerpt"\n      input: |\n${body}\n`;
}

// ---------------------------------------------------------------------------
// Proposal renderer (field-for-field aligned with sync-huntr renderProposal
// plus the _triage block from sync-ghsa).
// ---------------------------------------------------------------------------

function renderProposal(a: Advisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = a.cve_id ?? a.mcps_id;
  const category = categoryForAdvisory(a);
  const triage = isDetectionReady(a);
  const responseActions =
    a.severity === "critical" || a.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock =
    a.cve_aliases.length > 0
      ? `  cve:\n${a.cve_aliases.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cweBlock =
    a.cwes.length > 0
      ? `  cwe:\n${a.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const mcpsBlock = `  mcps_id:\n    - "${a.mcps_id}"\n`;
  const externalUrls = [...a.references, a.source_url];
  const externalBlock = `  external:\n${externalUrls
    .map((u) => `    - "${u}"`)
    .join("\n")}\n`;

  const title = a.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = `${a.details || a.title}`.replace(/\n+/g, " ").trim();
  const affectedNote =
    a.affected.length > 0 ? a.affected.join(", ") : "MCP server / client (unspecified)";

  const mitigationsYaml =
    a.mitigations.length > 0
      ? a.mitigations
          .map((m) => `    - "${m.replace(/"/g, '\\"')}"`)
          .join("\n")
      : "    []";

  return `# ATR rule proposal -- generated by scripts/sync-mcp-security-db.ts
# Source: CSA MCP-Security community vulnerability-db (${a.mcps_id})
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The advisory body /
#         reproduction steps are attached as a YAML comment under
#         detection.conditions for ease of conversion to a precision-safe
#         regex, and verbatim under _mcp_security_sync.advisory_body.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  CSA MCP-Security advisory ${a.mcps_id}${a.cve_id ? ` (${a.cve_id})` : ""}.
  Affected: ${affectedNote}.
  ${desc.slice(0, 600)}
author: "ATR Community (MCP Security DB sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${a.severity}

references:
${cveBlock}${cweBlock}${mcpsBlock}${externalBlock}
metadata_provenance:
  mcps_id: mcp-security-db-sync
${a.cve_aliases.length ? "  cve: mcp-security-db-sync\n" : ""}${a.cwes.length ? "  cwe: mcp-security-db-sync\n" : ""}
tags:
  category: ${category}
  subcategory: mcp-security-db-imported
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
    # TODO(human): convert the MCP advisory reproduction / payload below into
    # precision-safe detection.conditions regex/string matchers. Without this
    # work the rule will neither fire nor be promotable to rules/.
    #
    # === advisory reproduction / PoC excerpt ===
${pocCommentLines(a)}
    []

response:
  actions:
${responseActions.map((x) => `    - ${x}`).join("\n")}
  notify:
    - security_team

confidence: ${triage.ready ? 70 : 40}

test_cases:
${tpBlock(a)}  true_negatives:
    # TODO(human): add benign MCP tool calls / inputs that look similar to the
    # reproduction above but are legitimate -- required before promoting.
    []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason}"

# === sync-mcp-security-db.ts provenance ===
_mcp_security_sync:
  discovered_by: "CSA MCP-Security vulnerability-db via sync-mcp-security-db.ts"
  mcps_id: "${a.mcps_id}"
  cve: ${a.cve_id ? `"${a.cve_id}"` : "null"}
  cve_aliases: ${JSON.stringify(a.cve_aliases)}
  cwe: ${JSON.stringify(a.cwes)}
  affected: ${JSON.stringify(a.affected)}
  severity: "${a.severity}"
  cvss_vectors: ${JSON.stringify(a.cvss_vectors)}
  published: ${a.published ? `"${a.published}"` : "null"}
  source_url: "${a.source_url}"
  discovery_method: ${a.metadata.discovery_method ? `"${a.metadata.discovery_method.replace(/"/g, '\\"').slice(0, 300)}"` : "null"}
  fix_validation: ${a.metadata.fix_validation ? `"${a.metadata.fix_validation.replace(/"/g, '\\"').slice(0, 300)}"` : "null"}
  imported_at: "${new Date().toISOString()}"
  data_source_used: "git trees crawl of ${SOURCE_OWNER}/${SOURCE_REPO}@${SOURCE_REF}"
  mitigations:
${mitigationsYaml}
  reproduction_steps: |
${indentForLiteralBlock(a.metadata.reproduction_steps ?? "(none provided)", "    ")}
  advisory_body: |
${indentForLiteralBlock(a.details || "(no details body provided)", "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  advisories_found: number;
  advisories_parsed: number;
  parse_failures: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  skipped_existing: number;
  data_source_used: string | null;
  errors: string[];
  written_files: string[];
}

function emitSummary(summary: RunSummary): void {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::mcp-security-db-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      advisories_found: summary.advisories_found,
      advisories_parsed: summary.advisories_parsed,
      skipped_existing: summary.skipped_existing,
      parse_failures: summary.parse_failures,
      data_source_used: summary.data_source_used,
    })}`,
  );
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    advisories_found: 0,
    advisories_parsed: 0,
    parse_failures: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    skipped_existing: 0,
    data_source_used: null,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-mcp-security-db.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`source: ${SOURCE_OWNER}/${SOURCE_REPO}@${SOURCE_REF}`);
  if (!TOKEN)
    console.error(
      "note: no GITHUB_TOKEN/GH_TOKEN in env -- using 60-req/hr unauthenticated limit.",
    );

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // --- Crawl the advisory tree ---
  let listing: { paths: string[]; rateLimited: boolean; notFound: boolean };
  try {
    listing = await listAdvisoryPaths();
  } catch (e) {
    summary.errors.push(`tree crawl fatal: ${(e as Error).message}`);
    emitSummary(summary);
    process.exit(1);
  }

  if (listing.rateLimited) {
    summary.errors.push(
      "GitHub API rate limited -- set GITHUB_TOKEN and retry (recoverable).",
    );
    emitSummary(summary);
    process.exit(2);
  }
  if (listing.notFound || listing.paths.length === 0) {
    summary.errors.push(
      listing.notFound
        ? `repo/ref ${SOURCE_OWNER}/${SOURCE_REPO}@${SOURCE_REF} not found.`
        : "no advisory files found under advisories/ -- the path convention may have changed.",
    );
    emitSummary(summary);
    process.exit(2);
  }

  summary.advisories_found = listing.paths.length;
  summary.data_source_used = `git trees crawl (${listing.paths.length} advisory files)`;
  console.error(`found ${listing.paths.length} advisory file(s) under advisories/`);

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const path of listing.paths) {
    if (writtenCount >= LIMIT) break;

    let raw: string;
    try {
      raw = await fetchAdvisoryFile(path);
    } catch (e) {
      summary.parse_failures += 1;
      summary.errors.push(`fetch ${path}: ${(e as Error).message}`);
      continue;
    }

    const parsed = recordToAdvisory(path, raw);
    if ("error" in parsed) {
      summary.parse_failures += 1;
      if (VERBOSE) console.error(`  parse-skip ${path}: ${parsed.error}`);
      continue;
    }
    summary.advisories_parsed += 1;
    const a = parsed;

    // Dedup: by CVE alias OR by MCPS id (CVE is the cross-source primary key).
    if (!FORCE) {
      const cveHit = a.cve_aliases.find((c) => known.cves.has(c));
      if (cveHit) {
        summary.skipped_existing += 1;
        if (VERBOSE) console.error(`  have-rule ${cveHit}: already covered`);
        continue;
      }
      if (known.mcps.has(a.mcps_id)) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`  have-rule ${a.mcps_id}: already covered`);
        continue;
      }
    }

    const outName = `${a.cve_id ?? a.mcps_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const triage = isDetectionReady(a);
    const body = renderProposal(a);

    // Self-check: the rendered proposal must be parseable YAML.
    try {
      yaml.load(body);
    } catch (e) {
      summary.parse_failures += 1;
      summary.errors.push(
        `rendered YAML invalid for ${a.mcps_id}: ${(e as Error).message}`,
      );
      if (VERBOSE) console.error(`  render-skip ${a.mcps_id}: invalid YAML`);
      continue;
    }

    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName} (ready=${triage.ready})`);
    } else {
      console.error(`  would write ${outName} (ready=${triage.ready})`);
      if (VERBOSE && writtenCount === 0) {
        console.error("  --- sample rendered proposal (first match) ---");
        console.error(body);
        console.error("  --- end sample ---");
      }
    }
    writtenCount += 1;
  }

  emitSummary(summary);
  process.exit(0);
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
