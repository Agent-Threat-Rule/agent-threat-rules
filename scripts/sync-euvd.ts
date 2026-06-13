#!/usr/bin/env npx tsx
/**
 * sync-euvd.ts
 *
 * Pulls the ENISA EUVD (European Union Vulnerability Database) for AI / agent
 * / LLM / MCP vulnerabilities and emits ATR rule proposals under
 * proposals/euvd/<CVE-id-or-EUVD-id>.proposal.yaml.
 *
 * Why EUVD as a source
 * --------------------
 * EUVD is the EU's official vulnerability database, operated by ENISA under
 * the NIS2 Directive. Every EUVD entry aliases a CVE (and often a GHSA), so on
 * the surface there is heavy overlap with our NVD/GHSA syncs. The NET-NEW
 * value EUVD provides over those sources is:
 *   - EU-CERT (CERT-EU, CERT-PL, NCSC-NL, ...) sourced entries that may land in
 *     EUVD before / instead of NVD;
 *   - the EPSS exploitation-probability score attached per entry;
 *   - the "exploited in the wild" flag (membership of /exploitedvulnerabilities);
 *   - EUVD-only items that never got an NVD record.
 * Dedup is therefore by BOTH the CVE alias AND the enisaId, against rules/ and
 * every proposals/ subtree. Same CVE already covered by GHSA/NVD/etc → skip
 * (unless --force), but we still record the EUVD provenance (EPSS / exploited /
 * baseScore) in the proposal for the entries we do keep.
 *
 * API
 * ---
 *   Base: https://euvdservices.enisa.europa.eu/api   (no auth)
 *   - GET /search?text=<kw>&size=100&page=N  → { items: [...], total: N }
 *   - GET /enisaid?id=EUVD-YYYY-NNNNN        → single entry (richer)
 *   - GET /exploitedvulnerabilities          → { items, total } of in-the-wild
 *   Cross-checked against the community doc at github.com/bytew0lf/EUVD-API.
 *
 *   REAL item shape (verified live 2026-06-12):
 *     id            "EUVD-2026-36050"   (EUVD primary id)
 *     enisaUuid     uuid
 *     description   prose (no payloads — EUVD is advisory text, not PoC)
 *     datePublished "Jun 10, 2026, 2:31:10 PM"   (human string, not ISO)
 *     dateUpdated   "..."
 *     baseScore     7.1                  (CVSS base score, may be null)
 *     baseScoreVersion / baseScoreVector
 *     references    "url1\nurl2\n"       (NEWLINE-joined string, NOT an array)
 *     aliases       "GHSA-..\nCVE-2026-8335\n"  (NEWLINE-joined string)
 *     assigner      "CERT-PL"
 *     epss          85.27                (PERCENTAGE 0..100, may be 0 / null —
 *                    NOT the canonical 0..1 EPSS fraction; verified live)
 *     exploited     (only meaningful via /exploitedvulnerabilities membership;
 *                    the JSON field is usually null in /search items)
 *     enisaIdProduct [{ product: { name, vendor:{name} }, product_version }]
 *     enisaIdVendor  [{ vendor: { name } }]
 *
 * Detection-readiness
 * -------------------
 * EUVD descriptions are PROSE advisories — almost never a payload. So
 * detection_ready is true ONLY when the description contains payload-like
 * content (fenced code, an explicit payload/command string, an HTTP method +
 * path, etc.). In practice this is rare → most EUVD proposals are
 * tracking-only, identical in spirit to sync-ghsa / sync-cisa-kev.
 *
 * Secret discipline
 * -----------------
 * EUVD needs no auth. There is NO --key arg and nothing read from env. If the
 * service returns 401/403/429 (or is simply flaky / times out), we exit 2
 * (recoverable, daily cron retries) with a clear message — never a crash.
 *
 * Usage:
 *   npx tsx scripts/sync-euvd.ts                 # dry-run, all keywords
 *   npx tsx scripts/sync-euvd.ts --write         # write proposals
 *   npx tsx scripts/sync-euvd.ts --force         # overwrite existing
 *   npx tsx scripts/sync-euvd.ts --limit 5       # cap output
 *   npx tsx scripts/sync-euvd.ts --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected schema mismatch / bug)
 *   2 no data path available (recoverable — API down / 401/403/429 / timeout)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "euvd");

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

const API_BASE = "https://euvdservices.enisa.europa.eu/api";
const USER_AGENT =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";
const REQUEST_TIMEOUT_MS = 30_000;
const RATE_LIMIT_MS = 1_000; // polite spacing between EUVD requests
const PAGE_SIZE = 100;
const MAX_PAGES_PER_KEYWORD = 5; // bound the firehose per keyword

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// AI / agent / MCP search keywords. EUVD search matches the description text,
// so these pull agent-runtime-relevant entries (the agentRelevance gate below
// is still the final filter). Confirmed live: text=LLM returns Aix-DB SQL,
// Mem0 auth bypass, LiteLLM MCP RCE.
const KEYWORDS = [
  "LLM",
  "prompt injection",
  "agent",
  "MCP",
  "model context protocol",
  "langchain",
  "llama-index",
  "litellm",
];

// ---------------------------------------------------------------------------
// CWE → ATR category + agent-relevance gate (mirrors sync-ghsa.ts).
// EUVD entries rarely expose a structured CWE, so the keyword gate carries
// most of the weight here; CWE_TO_CATEGORY is kept for parity and for the rare
// entry whose description names a CWE.
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

// CWEs that map to an agent-runtime threat ATR can detect (same set as
// sync-ghsa.ts — code/command injection, SSRF, traversal, deserialization,
// SQLi, XSS, access control, info exposure). Deliberately excludes
// memory-safety / DoS CWEs (the TensorFlow-style kernel-crash noise).
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

// Agent-threat phrases (same intent as sync-ghsa.ts AGENT_THREAT_KEYWORDS).
// Bare "agent" is omitted (false-matches "user agent"); the keyword search
// already scopes to AI ecosystems.
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
  /\bllm\b/,
  /langchain/,
  /llama[- ]?index/,
  /litellm/,
  /\bssrf\b/,
  /server-side request/,
  /remote code execution/,
  /\brce\b/,
  /arbitrary code/,
  /arbitrary command/,
  /code execution/,
  /command injection/,
  /deserializ/,
  /sql injection/,
  /sql quer/,
  /path traversal/,
  /template injection/,
  /sandbox escape/,
  /exfiltrat/,
  /missing authoriz/,
  /authentication (?:check|bypass)/,
  /untrusted (input|data|manifest|model|content)/,
];

// EUVD entries that match a keyword but are clearly NOT agent-runtime
// (a stray "agent" or "llm" substring in an unrelated product) get dropped
// here. Relevant if it carries an agent-relevant CWE OR an agent-threat
// keyword in title/description/product names.
function agentRelevance(entry: EuvdEntry): {
  relevant: boolean;
  reason: string;
} {
  const cwes = entry.cwes;
  const hitCwe = cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const body = `${entry.description}\n${entry.productNames.join(" ")}`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  return {
    relevant: false,
    reason: `no agent-relevant CWE or keyword (cwes: ${cwes.join(",") || "none"})`,
  };
}

// ---------------------------------------------------------------------------
// EUVD wire types + normalization.
// ---------------------------------------------------------------------------

interface EuvdRawProductVendor {
  name?: string;
}
interface EuvdRawProductInner {
  name?: string;
  vendor?: EuvdRawProductVendor;
}
interface EuvdRawProduct {
  product?: EuvdRawProductInner;
  product_version?: string;
}
interface EuvdRawVendor {
  vendor?: { name?: string };
}
interface EuvdRawItem {
  id?: string;
  enisaUuid?: string;
  description?: string;
  datePublished?: string;
  dateUpdated?: string;
  baseScore?: number | null;
  baseScoreVersion?: string | null;
  baseScoreVector?: string | null;
  references?: string | null; // newline-joined
  aliases?: string | null; // newline-joined
  assigner?: string | null;
  epss?: number | null;
  exploited?: boolean | null;
  enisaIdProduct?: EuvdRawProduct[];
  enisaIdVendor?: EuvdRawVendor[];
}
interface EuvdSearchResponse {
  items?: EuvdRawItem[];
  total?: number;
}

// Normalized internal entry.
interface EuvdEntry {
  enisaId: string; // EUVD-YYYY-N
  cveId: string | null; // from aliases
  ghsaId: string | null; // from aliases (provenance only)
  otherAliases: string[];
  description: string;
  references: string[];
  cwes: string[]; // extracted from description if present
  baseScore: number | null;
  baseScoreVector: string | null;
  epss: number | null;
  exploited: boolean; // true iff present in /exploitedvulnerabilities
  assigner: string | null;
  datePublished: string | null;
  dateUpdated: string | null;
  products: string[]; // "vendor/product (version)"
  productNames: string[]; // just names, for relevance test
  euvdUrl: string;
}

function splitLines(s: string | null | undefined): string[] {
  if (!s || typeof s !== "string") return [];
  return s
    .split(/[\r\n]+/)
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

function extractCwes(text: string): string[] {
  const set = new Set<string>();
  const rx = /CWE-\d{1,5}/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(text)) !== null) {
    set.add(m[0].toUpperCase());
  }
  return [...set];
}

function normalizeEntry(
  raw: EuvdRawItem,
  exploitedIds: Set<string>,
): EuvdEntry | null {
  const enisaId = (raw.id || "").trim();
  if (!enisaId) return null;

  const aliases = splitLines(raw.aliases);
  let cveId: string | null = null;
  let ghsaId: string | null = null;
  const otherAliases: string[] = [];
  for (const a of aliases) {
    if (/^CVE-\d{4}-\d+$/i.test(a)) {
      if (!cveId) cveId = a.toUpperCase();
      else otherAliases.push(a);
    } else if (/^GHSA-/i.test(a)) {
      if (!ghsaId) ghsaId = a;
      else otherAliases.push(a);
    } else {
      otherAliases.push(a);
    }
  }

  const description = (raw.description || "").trim();
  const references = splitLines(raw.references);

  const products: string[] = [];
  const productNames: string[] = [];
  for (const p of raw.enisaIdProduct ?? []) {
    const name = p.product?.name?.trim();
    if (!name) continue;
    const vendor = p.product?.vendor?.name?.trim();
    const version = p.product_version?.trim();
    productNames.push(name);
    const label = [vendor ? `${vendor}/${name}` : name, version ? `(${version})` : ""]
      .filter(Boolean)
      .join(" ");
    products.push(label);
  }

  return {
    enisaId,
    cveId,
    ghsaId,
    otherAliases,
    description,
    references,
    cwes: extractCwes(description),
    baseScore: typeof raw.baseScore === "number" ? raw.baseScore : null,
    baseScoreVector: raw.baseScoreVector || null,
    epss: typeof raw.epss === "number" ? raw.epss : null,
    exploited: raw.exploited === true || exploitedIds.has(enisaId),
    assigner: raw.assigner || null,
    datePublished: raw.datePublished || null,
    dateUpdated: raw.dateUpdated || null,
    products,
    productNames,
    euvdUrl: `https://euvd.enisa.europa.eu/vulnerability/${enisaId}`,
  };
}

// ---------------------------------------------------------------------------
// HTTP with timeout + graceful 401/403/429 / flaky handling.
// Throws EuvdUnavailable for any recoverable condition so main() can exit 2.
// ---------------------------------------------------------------------------

class EuvdUnavailable extends Error {}

async function euvdGet(path: string): Promise<unknown> {
  const url = path.startsWith("http") ? path : `${API_BASE}${path}`;
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let resp: Response;
  try {
    resp = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": USER_AGENT },
      signal: controller.signal,
    });
  } catch (e) {
    // Network error, DNS, abort/timeout — all recoverable (service is flaky).
    throw new EuvdUnavailable(
      `EUVD request failed (${url}): ${(e as Error).message}`,
    );
  } finally {
    clearTimeout(t);
  }

  if (resp.status === 401 || resp.status === 403 || resp.status === 429) {
    throw new EuvdUnavailable(
      `EUVD returned ${resp.status} ${resp.statusText} for ${url} — ` +
        `treating as temporary (no auth is expected for this API). ` +
        `Daily cron will retry.`,
    );
  }
  if (resp.status >= 500 || resp.status === 408) {
    throw new EuvdUnavailable(
      `EUVD server error ${resp.status} ${resp.statusText} for ${url} — ` +
        `service appears flaky. Daily cron will retry.`,
    );
  }
  if (!resp.ok) {
    // 4xx other than the above: schema/route problem, surface as fatal-ish but
    // still recoverable so we never crash the cron.
    throw new EuvdUnavailable(
      `EUVD unexpected status ${resp.status} ${resp.statusText} for ${url}.`,
    );
  }

  const text = await resp.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new EuvdUnavailable(
      `EUVD returned non-JSON body for ${url} (first 200 chars: ` +
        `${text.slice(0, 200).replace(/\s+/g, " ")}).`,
    );
  }
}

// Fetch the set of EUVD ids currently flagged as exploited-in-the-wild.
// Best-effort: if this endpoint is down we proceed with exploited=false and
// note it in summary (we do NOT abort the whole run for the flag alone).
async function fetchExploitedIds(): Promise<{
  ids: Set<string>;
  ok: boolean;
  note: string;
}> {
  const ids = new Set<string>();
  try {
    const data = (await euvdGet(
      `/exploitedvulnerabilities?size=${PAGE_SIZE}&page=0`,
    )) as EuvdSearchResponse | EuvdRawItem[];
    const items = Array.isArray(data) ? data : (data.items ?? []);
    for (const it of items) if (it.id) ids.add(it.id.trim());
    return { ids, ok: true, note: `${ids.size} exploited ids loaded` };
  } catch (e) {
    return {
      ids,
      ok: false,
      note: `exploited-ids fetch skipped: ${(e as Error).message}`,
    };
  }
}

// Page through /search for one keyword, merging items. Stops at total or
// MAX_PAGES_PER_KEYWORD, whichever comes first.
async function searchKeyword(
  keyword: string,
  exploitedIds: Set<string>,
): Promise<EuvdEntry[]> {
  const out: EuvdEntry[] = [];
  let page = 0;
  let total = Infinity;
  while (page < MAX_PAGES_PER_KEYWORD && page * PAGE_SIZE < total) {
    const qs =
      `/search?text=${encodeURIComponent(keyword)}` +
      `&size=${PAGE_SIZE}&page=${page}`;
    const data = (await euvdGet(qs)) as EuvdSearchResponse;
    if (!data || typeof data !== "object" || !Array.isArray(data.items)) {
      throw new EuvdUnavailable(
        `EUVD /search for "${keyword}" returned unexpected shape ` +
          `(no items[]). API contract may have changed.`,
      );
    }
    total = typeof data.total === "number" ? data.total : data.items.length;
    for (const raw of data.items) {
      const norm = normalizeEntry(raw, exploitedIds);
      if (norm) out.push(norm);
    }
    if (data.items.length < PAGE_SIZE) break; // last page
    page += 1;
    await sleep(RATE_LIMIT_MS);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE / EUVD ids across rules/ + proposals/.
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
  euvds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const euvds = new Set<string>();
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
          references?: { cve?: string[]; euvd?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
      if (refs?.euvd) {
        const v = refs.euvd;
        if (typeof v === "string") euvds.add(v);
        else if (Array.isArray(v))
          for (const e of v) if (typeof e === "string") euvds.add(e);
      }
      // Also pick up an EUVD id mentioned in the filename.
      const m = f.match(/EUVD-\d{4}-\d+/i);
      if (m) euvds.add(m[0].toUpperCase());
    }
  }
  return { cves, euvds };
}

// ---------------------------------------------------------------------------
// Detection-readiness: EUVD is prose. Ready only if payload-like content.
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
    "prompt: ['\"]",
    "\\$\\(", // command substitution
    ";\\s*(?:rm|curl|wget|cat|nc)\\b",
  ].join("|"),
  "im",
);

function isDetectionReady(entry: EuvdEntry): {
  ready: boolean;
  reason: string;
} {
  if (PAYLOAD_HEURISTICS_RX.test(entry.description))
    return { ready: true, reason: "payload-like content in EUVD description" };
  if (entry.references.some((r) => /poc|exploit-db|cve\.org/i.test(r)))
    return { ready: true, reason: "PoC reference link present" };
  return {
    ready: false,
    reason: "EUVD description is prose with no reproducer / payload section",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer (aligned to sync-huntr / sync-ghsa schema).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see euvd url for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function severityFromScore(score: number | null): string {
  if (score === null) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function renderProposal(entry: EuvdEntry): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = entry.cveId ?? entry.enisaId;
  const draftIdSuffix = entry.cveId
    ? entry.cveId.replace(/^CVE-/, "")
    : entry.enisaId;
  const category = guessCategory(entry.cwes);
  const severity = severityFromScore(entry.baseScore);
  const triage = isDetectionReady(entry);

  const responseActions =
    severity === "critical" || severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const title = (
    entry.description.split(/[.\n]/)[0] || entry.enisaId
  )
    .replace(/"/g, '\\"')
    .slice(0, 120);

  const descOneLine = entry.description.replace(/\n+/g, " ").trim();

  const cveBlock = entry.cveId ? `  cve:\n    - "${entry.cveId}"\n` : "";
  const cweBlock =
    entry.cwes.length > 0
      ? `  cwe:\n${entry.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const euvdBlock = `  euvd:\n    - "${entry.enisaId}"\n`;
  // external refs = source references[] + the canonical EUVD vulnerability URL.
  const externalRefs = [...entry.references, entry.euvdUrl].filter(
    (r, i, arr) => arr.indexOf(r) === i,
  );
  const externalBlock =
    externalRefs.length > 0
      ? `  external:\n${externalRefs.map((u) => `    - "${u}"`).join("\n")}\n`
      : "";

  const products =
    entry.products.length > 0
      ? entry.products
      : entry.productNames.length > 0
        ? entry.productNames
        : ["unknown"];

  return `# ATR rule proposal -- generated by scripts/sync-euvd.ts
# Source: ENISA EUVD (EU Vulnerability Database) ${entry.enisaId}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. EUVD advisory body is
#         attached under _euvd_sync.advisory_body for conversion to a
#         precision-safe regex.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  ENISA EUVD ${entry.enisaId}${entry.cveId ? ` (${entry.cveId})` : ""}.
  Affected: ${products.join("; ").replace(/\n+/g, " ").slice(0, 200)}.
  ${descOneLine.slice(0, 600)}
author: "ATR Community (EUVD sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${cweBlock}${euvdBlock}${externalBlock}
metadata_provenance:
  euvd: euvd-sync
${entry.cveId ? "  cve: euvd-sync\n" : ""}${entry.cwes.length ? "  cwe: euvd-sync\n" : ""}
tags:
  category: ${category}
  subcategory: euvd-imported
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
    # TODO(human): convert the EUVD advisory body (see _euvd_sync.advisory_body)
    # into precision-safe detection.conditions regex/string matchers. EUVD is
    # prose, so most entries need a human to derive the attack pattern before
    # the rule can fire or be promoted to rules/.
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

# === sync-euvd.ts provenance ===
_euvd_sync:
  enisa_id: "${entry.enisaId}"
  cve_id: ${entry.cveId ? `"${entry.cveId}"` : "null"}
  ghsa_id: ${entry.ghsaId ? `"${entry.ghsaId}"` : "null"}
  other_aliases: ${JSON.stringify(entry.otherAliases)}
  assigner: ${entry.assigner ? `"${entry.assigner.replace(/"/g, '\\"')}"` : "null"}
  base_score: ${entry.baseScore ?? "null"}
  base_score_vector: ${entry.baseScoreVector ? `"${entry.baseScoreVector}"` : "null"}
  # epss is an EXPLOIT-PREDICTION PERCENTAGE (0-100) as returned by EUVD,
  # NOT the canonical 0..1 EPSS fraction. Divide by 100 for the standard score.
  epss_percent: ${entry.epss ?? "null"}
  exploited: ${entry.exploited}
  affected_products:
${products.map((p) => `    - "${p.replace(/"/g, '\\"')}"`).join("\n")}
  date_published: ${entry.datePublished ? `"${entry.datePublished.replace(/"/g, '\\"')}"` : "null"}
  date_updated: ${entry.dateUpdated ? `"${entry.dateUpdated.replace(/"/g, '\\"')}"` : "null"}
  euvd_url: "${entry.euvdUrl}"
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(entry.description || "(no description provided by EUVD API)", "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  keywords: string[];
  entries_fetched: number;
  unique_entries: number;
  filtered_not_agent: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  exploited_flagged: number;
  exploited_ids_note: string;
  errors: string[];
  written_files: string[];
}

function printSummaryAndMarker(summary: RunSummary): void {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::euvd-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      unique_entries: summary.unique_entries,
      filtered_not_agent: summary.filtered_not_agent,
      already_known: summary.already_known,
      exploited_flagged: summary.exploited_flagged,
    })}`,
  );
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    keywords: KEYWORDS,
    entries_fetched: 0,
    unique_entries: 0,
    filtered_not_agent: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    exploited_flagged: 0,
    exploited_ids_note: "",
    errors: [],
    written_files: [],
  };

  console.error("=== sync-euvd.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // Step 0: exploited-in-the-wild id set (best-effort, never aborts the run).
  const exploited = await fetchExploitedIds();
  summary.exploited_ids_note = exploited.note;
  if (VERBOSE) console.error(`exploited ids: ${exploited.note}`);

  // Step 1: search each keyword, merge + dedup by enisaId (CVE alias used for
  // cross-source dedup against the known index later).
  const byEnisaId = new Map<string, EuvdEntry>();
  try {
    for (const kw of KEYWORDS) {
      const entries = await searchKeyword(kw, exploited.ids);
      summary.entries_fetched += entries.length;
      if (VERBOSE)
        console.error(`keyword "${kw}": ${entries.length} entries`);
      for (const e of entries) {
        const existing = byEnisaId.get(e.enisaId);
        if (!existing) byEnisaId.set(e.enisaId, e);
        // already merged across keywords; keep first (identical payloads).
      }
      await sleep(RATE_LIMIT_MS);
    }
  } catch (e) {
    if (e instanceof EuvdUnavailable) {
      summary.errors.push(e.message);
      console.error(`EUVD unavailable: ${e.message}`);
      // If we got nothing at all, this is the no-data path → exit 2.
      if (byEnisaId.size === 0) {
        printSummaryAndMarker(summary);
        process.exit(2);
      }
      // Otherwise proceed with what we have (partial result still useful).
      console.error(
        `proceeding with ${byEnisaId.size} entries gathered before failure`,
      );
    } else {
      throw e; // genuine bug → fatal (exit 1 via catch below)
    }
  }

  const unique = [...byEnisaId.values()];
  summary.unique_entries = unique.length;
  if (VERBOSE)
    console.error(`unique entries after merge: ${unique.length}`);

  if (unique.length === 0) {
    summary.errors.push(
      "No EUVD entries returned for any keyword — API may be down or the " +
        "search contract changed. Recoverable; daily cron will retry.",
    );
    printSummaryAndMarker(summary);
    process.exit(2);
  }

  // Step 2: agent-relevance gate + dedup against rules/ + proposals/.
  const known = buildKnownIndex();
  let writtenCount = 0;

  // Process exploited / higher-score first so a --limit run keeps the
  // most-valuable EUVD entries (the net-new EPSS / exploited signal).
  unique.sort((a, b) => {
    if (a.exploited !== b.exploited) return a.exploited ? -1 : 1;
    const ea = a.epss ?? 0;
    const eb = b.epss ?? 0;
    if (eb !== ea) return eb - ea;
    return (b.baseScore ?? 0) - (a.baseScore ?? 0);
  });

  for (const entry of unique) {
    if (writtenCount >= LIMIT) break;

    const relevance = agentRelevance(entry);
    if (!relevance.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(
          `  skip (not agent) ${entry.enisaId}: ${relevance.reason}`,
        );
      continue;
    }

    // Dedup: CVE alias OR enisaId already covered anywhere.
    if (!FORCE && entry.cveId && known.cves.has(entry.cveId)) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(
          `  have-rule ${entry.cveId} (via ${entry.enisaId}): already covered`,
        );
      continue;
    }
    if (!FORCE && known.euvds.has(entry.enisaId.toUpperCase())) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-rule ${entry.enisaId}: already covered`);
      continue;
    }

    const outName = `${entry.cveId ?? entry.enisaId}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    const triage = isDetectionReady(entry);
    const body = renderProposal(entry);

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(
        `  would write ${outName}` +
          (entry.exploited ? " [EXPLOITED]" : "") +
          (entry.epss ? ` epss=${entry.epss}` : "") +
          ` (${triage.ready ? "detection_ready" : "tracking_only"})`,
      );
    }

    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    if (entry.exploited) summary.exploited_flagged += 1;
    writtenCount += 1;
  }

  printSummaryAndMarker(summary);
  process.exit(0);
}

// Run only when invoked as a script (not when imported for tests).
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}

export { agentRelevance, normalizeEntry, isDetectionReady, renderProposal };
