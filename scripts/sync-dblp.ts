#!/usr/bin/env npx tsx
/**
 * sync-dblp.ts
 *
 * Pulls DBLP (the authoritative computer-science bibliography) for top-venue
 * agent/LLM-attack papers and emits ATR rule proposals under
 * proposals/dblp/<id>.proposal.yaml.
 *
 * WHY DBLP IS A RADAR SOURCE (NOT A CVE SOURCE)
 * ---------------------------------------------
 * GHSA / Huntr / NVD are CVE sources: each entry is a confirmed vuln in a
 * specific package, with a CVE id and a reproducer/PoC. DBLP is a different
 * animal entirely — it is a BIBLIOGRAPHY. A DBLP hit is publication metadata:
 * title, authors, venue (USENIX Security, IEEE S&P, ACM CCS, NDSS, ...), year,
 * and a doi/ee link. There is NO abstract, NO body text, and absolutely NO
 * payload. This makes DBLP a SIBLING of sync-arxiv.ts (the other academic
 * radar), but even more metadata-only than arXiv: arXiv at least carries an
 * abstract; DBLP carries only the title.
 *
 * Consequences (mirrors sync-arxiv.ts, tightened):
 *   - detection_ready is ALWAYS false. There is no payload and not even an
 *     abstract to triage from — these are tracking-only pointers to research.
 *     They are NOT auto-promotable to rules/ by promote-detection-ready.ts.
 *   - Proposal id is `DBLP-<hash>` where the hash is derived from the stable
 *     DBLP key (e.g. conf/uss/Foo24). When the hit has a DOI we prefer a
 *     doi-based id so the same paper across sources collides on a stable key.
 *   - The title + authors + venue go into `_dblp_sync.advisory_body` so a
 *     future reviewer has the bibliographic context inline. references.external
 *     is the doi/ee URL.
 *
 * VENUE / RELEVANCE FILTER
 * ------------------------
 * Used as a TOP-VENUE radar. We rotate a fixed query set against the DBLP
 * publication search API, then keep a hit only if:
 *   (a) it is recent (2025 or 2026), AND
 *   (b) its title is agent/LLM-attack relevant (an LLM/agent term AND an
 *       attack term, or an unambiguous strong phrase like "prompt injection").
 * Top-venue hits (USENIX Security / IEEE S&P / CCS / NDSS) are surfaced first
 * in verbose output and tagged, but non-top-venue agent-attack papers are still
 * kept (the radar should not miss a relevant TIFS / arXiv-mirrored paper just
 * because the venue string differs). The recency + relevance gate is what keeps
 * the firehose down, not the venue allowlist.
 *
 * DEDUP (buildKnownIndex)
 * -----------------------
 * Mirrors sync-huntr / sync-arxiv: walk rules/ + proposals/ and collect
 *   - DBLP keys / DBLP-<hash> ids (this source's primary key)
 *   - DOIs (references.doi and any doi.org URL in references.external)
 *   - normalized titles (lowercased, alnum-only) — CRITICAL because the SAME
 *     paper frequently appears in BOTH arXiv and DBLP. We must not emit a DBLP
 *     proposal for a paper sync-arxiv.ts already tracked. The arXiv proposals
 *     store the paper title in their top-level `title:` field, so the
 *     normalized-title index catches that overlap.
 *
 * API
 * ---
 *   https://dblp.org/search/publ/api?q=<query>&format=json&h=100   (no auth)
 * Verified live 2026-06-12 (200 OK). Polite UA, courtesy delay between queries.
 *
 * Usage:
 *   npx tsx scripts/sync-dblp.ts                 # dry-run
 *   npx tsx scripts/sync-dblp.ts --write         # write proposals
 *   npx tsx scripts/sync-dblp.ts --force         # overwrite / ignore dedup
 *   npx tsx scripts/sync-dblp.ts --verbose
 *   npx tsx scripts/sync-dblp.ts --limit 30      # default cap ~30
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error)
 *   2 no data path available (recoverable — every query non-200 / empty)
 */

import {
  createHash,
} from "node:crypto";
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "dblp");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const DEFAULT_LIMIT = 30;
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : DEFAULT_LIMIT;

const POLITE_UA =
  "ATR-Sync/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// DBLP publication search API. h=100 returns up to 100 hits per query.
const DBLP_ENDPOINT = "https://dblp.org/search/publ/api";
const DBLP_HITS_PER_QUERY = 100;

// Queries rotated against the API (per task brief). Each is a distinct facet
// of the agent/LLM attack surface; union + dedup by DBLP key.
const QUERIES = [
  "prompt injection",
  "LLM agent security",
  "jailbreak",
  "tool poisoning",
  "MCP security",
  "indirect prompt injection",
];

// Recency window — radar keeps only the research frontier.
const RECENT_YEARS = new Set(["2025", "2026"]);

// Top venues we explicitly surface (per task brief). Hits at these venues are
// flagged top_venue=true; non-top venues are still kept if relevant.
const TOP_VENUES: Record<string, RegExp> = {
  "USENIX Security": /\buss\b|usenix security|usenix-security/i,
  "IEEE S&P": /\bsp\b|ieee s&p|s&p|symposium on security and privacy|oakland/i,
  "ACM CCS": /\bccs\b|computer and communications security/i,
  NDSS: /\bndss\b|network and distributed system security/i,
};

const FETCH_TIMEOUT_MS = 30_000;
// DBLP rate-limits bursts with HTTP 429. Empirically ~4s between queries is
// safe; 1.5s draws 429s. Space queries out and back off on 429.
const QUERY_DELAY_MS = 4_000;
const MAX_429_RETRIES = 2;
const RETRY_BACKOFF_MS = 6_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Agent/LLM security relevance filter (title-only — DBLP has no abstract).
// Same shape as sync-arxiv.ts securityRelevance, applied to the title string.
// ---------------------------------------------------------------------------

const LLM_AGENT_TERMS: RegExp[] = [
  /\bllms?\b/i,
  /large language model/i,
  /\bgpt\b/i,
  /\bllm[- ]agent/i,
  /\bai[- ]agent/i,
  /agentic/i,
  /multi[- ]agent/i,
  /language[- ]model agent/i,
  /tool[- ](use|using|call|calling|invocation)/i,
  /function[- ]calling/i,
  /\bmcp\b/i,
  /model context protocol/i,
  /retrieval[- ]augmented/i,
  /\brag\b/i,
  /gui agent/i,
  /computer[- ]use agent/i,
  /chatbot/i,
  /\bvlm\b/i,
  /vision[- ]language (model|agent)/i,
];

const ATTACK_TERMS: RegExp[] = [
  /injection/i,
  /jailbreak/i,
  /poison/i,
  /exfiltrat/i,
  /hijack/i,
  /adversarial/i,
  /backdoor/i,
  /\battack/i,
  /malicious/i,
  /exploit/i,
  /data leak/i,
  /privacy (exposure|leak)/i,
  /sandbox escape/i,
  /privilege escalation/i,
];

// Phrases that already encode BOTH an LLM/agent context AND an attack —
// accepted on the title alone (they cannot match a non-LLM CS paper).
const STRONG_PHRASES: RegExp[] = [
  /prompt injection/i,
  /indirect prompt injection/i,
  /\bmemory poisoning/i,
  /\brag poisoning/i,
  /tool poisoning/i,
  /agent hijack/i,
  /\bjailbreak/i,
];

interface RelevanceResult {
  relevant: boolean;
  reason: string;
}

function securityRelevance(title: string): RelevanceResult {
  const hay = title;
  const strong = STRONG_PHRASES.find((rx) => rx.test(hay));
  if (strong) return { relevant: true, reason: `strong phrase /${strong.source}/` };
  const llm = LLM_AGENT_TERMS.find((rx) => rx.test(hay));
  if (!llm) return { relevant: false, reason: "no LLM/agent term in title" };
  const atk = ATTACK_TERMS.find((rx) => rx.test(hay));
  if (!atk)
    return {
      relevant: false,
      reason: `LLM term /${llm.source}/ but no attack term in title`,
    };
  return {
    relevant: true,
    reason: `LLM /${llm.source}/ + attack /${atk.source}/`,
  };
}

// ---------------------------------------------------------------------------
// Category mapping — best-effort from the title (sync-arxiv categoryForPaper).
// ---------------------------------------------------------------------------

function categoryForPaper(title: string): string {
  const h = title.toLowerCase();
  if (/prompt[- ]injection|jailbreak|adversarial suffix|system prompt (leak|extract)/.test(h))
    return "prompt-injection";
  if (/tool[- ]poison|mcp|model context protocol|malicious tool|tool[- ]description/.test(h))
    return "tool-poisoning";
  if (/(rag|memory|knowledge[- ]base|retrieval)[- ]?poison|data poison|backdoor/.test(h))
    return "data-poisoning";
  if (/exfiltrat|data leak|privacy (exposure|leak)|information (leak|disclos)|sensitive (data|info)/.test(h))
    return "context-exfiltration";
  if (/privilege escalation|excessive (autonomy|agency|permission)|unauthor/.test(h))
    return "privilege-escalation";
  if (/hijack|takeover|remote code|command injection|sandbox escape/.test(h))
    return "tool-poisoning";
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// DBLP hit model + JSON extraction.
// ---------------------------------------------------------------------------

interface DblpPaper {
  dblp_key: string; // e.g. "conf/uss/Foo24" — stable across DBLP
  title: string;
  authors: string[];
  venue: string;
  year: string;
  doi: string | null;
  link: string; // ee or doi URL
  type: string; // "Conference and Workshop Papers" | "Journal Articles" | ...
  top_venue: string | null; // matched TOP_VENUES label, if any
}

// DBLP returns author text and venue as either a single string or an array of
// objects/strings depending on cardinality. Normalize both shapes.
function asArray<T>(v: T | T[] | undefined | null): T[] {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

function textOf(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === "string") return v;
  if (typeof v === "object" && "text" in (v as Record<string, unknown>)) {
    const t = (v as Record<string, unknown>).text;
    return typeof t === "string" ? t : null;
  }
  return null;
}

function parseAuthors(info: Record<string, unknown>): string[] {
  const a = info.authors as { author?: unknown } | undefined;
  if (!a?.author) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of asArray(a.author)) {
    let name = textOf(raw);
    if (!name) continue;
    // DBLP disambiguates homonyms with a trailing numeric suffix
    // ("Ying Wang 0009"). Strip it for display.
    name = name.replace(/\s+\d{4}$/, "").trim();
    if (name && !seen.has(name)) {
      seen.add(name);
      out.push(name);
    }
  }
  return out;
}

function topVenueFor(venue: string, dblpKey: string): string | null {
  // Venue may be a display name ("USENIX Security") or the key encodes the
  // venue slug ("conf/uss/..."). Check both.
  const hay = `${venue} ${dblpKey}`;
  for (const [label, rx] of Object.entries(TOP_VENUES)) {
    if (rx.test(hay)) return label;
  }
  return null;
}

interface DblpHit {
  info?: {
    title?: string;
    authors?: { author?: unknown };
    venue?: unknown;
    year?: string;
    type?: string;
    key?: string;
    doi?: string;
    ee?: unknown;
    url?: string;
  };
}

function parseHits(json: unknown): DblpPaper[] {
  const root = json as {
    result?: { hits?: { hit?: DblpHit | DblpHit[] } };
  };
  const hits = asArray(root?.result?.hits?.hit);
  const papers: DblpPaper[] = [];
  for (const h of hits) {
    const info = h.info;
    if (!info) continue;
    const title = (info.title ?? "").replace(/\s+/g, " ").trim().replace(/\.$/, "");
    const key = (info.key ?? "").trim();
    if (!title || !key) continue;
    const year = (info.year ?? "").toString().trim();
    // venue can be a string or array of strings/objects (proceedings + series).
    const venue =
      asArray(info.venue)
        .map((v) => textOf(v) ?? (typeof v === "string" ? v : ""))
        .filter(Boolean)
        .join(", ") || "(unknown venue)";
    const doi = (info.doi ?? "").toString().trim() || null;
    // ee is the canonical external link; fall back to doi.org or the DBLP rec.
    const ee =
      asArray(info.ee)
        .map((e) => textOf(e) ?? (typeof e === "string" ? e : ""))
        .filter(Boolean)[0] || null;
    const link =
      ee ||
      (doi ? `https://doi.org/${doi}` : null) ||
      (info.url ?? `https://dblp.org/rec/${key}`);
    papers.push({
      dblp_key: key,
      title,
      authors: parseAuthors(info as Record<string, unknown>),
      venue,
      year,
      doi,
      link,
      type: (info.type ?? "").toString().trim(),
      top_venue: topVenueFor(venue, key),
    });
  }
  return papers;
}

// ---------------------------------------------------------------------------
// Fetching.
// ---------------------------------------------------------------------------

async function fetchDblp(query: string): Promise<DblpPaper[] | null> {
  const url =
    `${DBLP_ENDPOINT}?q=${encodeURIComponent(query)}` +
    `&format=json&h=${DBLP_HITS_PER_QUERY}`;
  for (let attempt = 0; attempt <= MAX_429_RETRIES; attempt++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      const res = await fetch(url, {
        headers: { "User-Agent": POLITE_UA, Accept: "application/json" },
        signal: ctrl.signal,
      });
      clearTimeout(t);
      // 429 / 503: DBLP throttling — back off and retry.
      if ((res.status === 429 || res.status === 503) && attempt < MAX_429_RETRIES) {
        const retryAfter = parseInt(res.headers.get("retry-after") ?? "", 10);
        const wait = Number.isFinite(retryAfter)
          ? retryAfter * 1000
          : RETRY_BACKOFF_MS * (attempt + 1);
        if (VERBOSE)
          console.error(`    DBLP ${res.status} for "${query}" -- backing off ${wait}ms (retry ${attempt + 1}/${MAX_429_RETRIES})`);
        await sleep(wait);
        continue;
      }
      if (!res.ok) {
        console.error(`non-200 from DBLP for "${query}": ${res.status} ${res.statusText}`);
        return null;
      }
      const json = await res.json();
      return parseHits(json);
    } catch (e) {
      console.error(`fetch error for DBLP "${query}": ${(e as Error).message}`);
      return null;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Stable id. Prefer a doi-based key; fall back to the DBLP key. Both run
// through a short sha1 so the proposal filename is fixed-length and filesystem
// safe (DBLP keys and DOIs contain slashes).
// ---------------------------------------------------------------------------

function stableId(p: DblpPaper): string {
  const basis = p.doi ? `doi:${p.doi}` : `dblp:${p.dblp_key}`;
  const hash = createHash("sha1").update(basis).digest("hex").slice(0, 12);
  return `DBLP-${hash}`;
}

// ---------------------------------------------------------------------------
// Normalized title for cross-source (esp. arXiv) dedup.
// ---------------------------------------------------------------------------

function normalizeTitle(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

// ---------------------------------------------------------------------------
// Idempotency: index existing DBLP ids / DOIs / normalized titles across
// rules/ + proposals/.
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

const DOI_RX = /10\.\d{4,9}\/[^\s"'<>)\]]+/g;

function doisFromValue(v: unknown, into: Set<string>): void {
  if (typeof v === "string") {
    const m = v.match(DOI_RX);
    if (m) for (const d of m) into.add(d.toLowerCase().replace(/[).,;]+$/, ""));
  } else if (Array.isArray(v)) {
    for (const x of v) doisFromValue(x, into);
  }
}

interface KnownIndex {
  ids: Set<string>; // DBLP-<hash> ids and raw DBLP keys
  dois: Set<string>;
  titles: Set<string>; // normalized titles (catches arXiv overlap)
}

function buildKnownIndex(): KnownIndex {
  const ids = new Set<string>();
  const dois = new Set<string>();
  const titles = new Set<string>();
  for (const dir of [RULES_DIR, PROPOSALS_BASE]) {
    for (const f of walkYaml(dir)) {
      // Fast path: filename pattern DBLP-<hash>.proposal.yaml
      const fm = f.match(/DBLP-[a-f0-9]{12}/i);
      if (fm) ids.add(fm[0]);

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
      if (typeof doc !== "object" || doc === null) continue;
      const d = doc as Record<string, unknown>;

      // id (ATR-DRAFT-DBLP-<hash>) and dblp key from _dblp_sync.
      const id = d.id;
      if (typeof id === "string") {
        const m = id.match(/DBLP-[a-f0-9]{12}/i);
        if (m) ids.add(m[0]);
      }
      const sync = d._dblp_sync as { dblp_key?: string } | undefined;
      if (sync?.dblp_key) ids.add(sync.dblp_key);

      // DOIs from references (doi field and any doi in external URLs).
      const refs = d.references as Record<string, unknown> | undefined;
      if (refs) {
        doisFromValue(refs.doi, dois);
        doisFromValue(refs.external, dois);
      }

      // Normalized title — catches the SAME paper already tracked by sync-arxiv
      // (arXiv proposals carry the paper title in their top-level `title:`).
      const title = d.title;
      if (typeof title === "string" && title.trim()) {
        const norm = normalizeTitle(title);
        if (norm.length >= 8) titles.add(norm);
      }
    }
  }
  return { ids, dois, titles };
}

// ---------------------------------------------------------------------------
// Proposal renderer. Field-for-field aligned with sync-arxiv/sync-huntr, with
// the research-radar specializations: detection_ready ALWAYS false, no CVE, no
// payload, confidence low, advisory_body = title + authors + venue.
// ---------------------------------------------------------------------------

// Escape a value for a YAML double-quoted scalar. DBLP titles and author names
// carry diacritics and the occasional backslash; double the backslash before
// escaping the quote (same fix sync-arxiv.ts uses).
function yq(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function renderProposal(p: DblpPaper): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = stableId(p);
  const category = categoryForPaper(p.title);
  const title = yq(p.title.replace(/\s+/g, " ").slice(0, 120));
  const authorList = p.authors.length ? p.authors.join(", ") : "(authors not listed)";
  const descOneLine =
    `${p.title} — ${authorList} @ ${p.venue} ${p.year}`.slice(0, 600);
  const authorsBlock =
    p.authors.length > 0
      ? p.authors.map((a) => `    - "${yq(a)}"`).join("\n")
      : "    []";

  // Bibliographic body — embedded as YAML comment lines under
  // detection.conditions so a human reviewer sees the pointer inline. There is
  // no payload here (it's a citation), so this is context, never a PoC.
  const bibForComment = [
    p.title,
    `Authors: ${authorList}`,
    `Venue: ${p.venue} (${p.year})${p.top_venue ? ` [TOP VENUE: ${p.top_venue}]` : ""}`,
    p.doi ? `DOI: ${p.doi}` : `Link: ${p.link}`,
  ].join("\n");
  const bibCommentLines = bibForComment
    .split("\n")
    .filter((s) => s.trim().length > 0)
    .map((s) => `    # ${s}`)
    .join("\n");

  const advisoryBody = [
    p.title,
    "",
    `Authors: ${authorList}`,
    `Venue: ${p.venue}`,
    `Year: ${p.year}`,
    p.top_venue ? `Top venue: ${p.top_venue}` : "",
    p.type ? `Type: ${p.type}` : "",
    p.doi ? `DOI: ${p.doi}` : "",
    `Link: ${p.link}`,
    `DBLP key: ${p.dblp_key}`,
  ]
    .filter((l) => l !== "")
    .map((l) => `    ${l}`)
    .join("\n");

  return `# ATR rule proposal -- generated by scripts/sync-dblp.ts
# Source: DBLP bibliography record ${p.dblp_key} (top-venue academic radar)
# Imported on: ${today}
# Status: DRAFT -- this is a RESEARCH-RADAR / TRACKING-ONLY entry, NOT a
#         confirmed vulnerability. A DBLP record is publication metadata
#         (title + authors + venue + DOI) -- there is NO CVE, NO abstract, and
#         NO inline payload. detection_ready is FALSE: this is a pointer to
#         peer-reviewed agent/LLM attack research for human/LLM triage, and is
#         NOT auto-promotable to rules/ by promote-detection-ready.ts. If a PoC
#         is later obtained from the paper, author a separate detection
#         proposal from THAT payload.
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  DBLP top-venue research-radar entry (${p.dblp_key}): peer-reviewed
  agent/LLM attack paper. ${descOneLine}
author: "ATR Community (DBLP sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: medium

references:
${p.doi ? `  doi:\n    - "${yq(p.doi)}"\n` : ""}  external:
    - "${yq(p.link)}"

metadata_provenance:
  dblp: dblp-sync
${p.doi ? "  doi: dblp-sync\n" : ""}
tags:
  category: ${category}
  subcategory: research-radar
  scan_target: runtime
  confidence: low

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
    # TODO(human): this is a bibliographic radar entry, not a confirmed vuln.
    # There is NO extractable payload here -- only a citation. If the attack
    # class proves real and a PoC is obtained from the paper, author a
    # detection proposal from THAT payload -- do not regex the title.
    #
    # === paper citation (bibliographic pointer, not a payload) ===
${bibCommentLines}
    []

response:
  actions:
    - alert
  notify:
    - security_team

confidence: 25

test_cases:
  true_positives: []
  true_negatives: []

# === sync-dblp.ts provenance ===
_dblp_sync:
  discovered_by: "DBLP publication search via sync-dblp.ts"
  dblp_key: "${yq(p.dblp_key)}"
  doi: ${p.doi ? `"${yq(p.doi)}"` : "null"}
  venue: "${yq(p.venue)}"
  year: "${yq(p.year)}"
  top_venue: ${p.top_venue ? `"${yq(p.top_venue)}"` : "null"}
  publication_type: "${yq(p.type)}"
  source: "${yq(p.link)}"
  authors:
${authorsBlock}
  imported_at: "${new Date().toISOString()}"
  data_source_used: "DBLP search/publ API"
  advisory_body: |
${advisoryBody}

# Triage flag read by promote-detection-ready.ts. DBLP records are
# bibliographic metadata: no CVE, no abstract, no inline payload. ALWAYS
# detection_ready=false -- these are tracking-only research-radar pointers,
# never auto-promotable to rules.
_triage:
  detection_ready: false
  reason: "DBLP bibliography record -- title/author/venue metadata only, no CVE / no abstract / no inline payload (tracking-only radar)"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  queries_run: string[];
  queries_failed: string[];
  hits_seen: number; // unique DBLP keys fetched
  recent_filtered_out: number; // dropped: not 2025/2026
  relevance_filtered_out: number; // dropped: title not agent-attack
  in_scope: number; // recent + relevant
  top_venue_hits: number;
  skipped_existing: number; // dedup against rules/ + proposals/ (incl. arXiv)
  new_proposals: number;
  data_source_used: string | null;
  written_files: string[];
  errors: string[];
}

async function gatherPapers(summary: RunSummary): Promise<DblpPaper[]> {
  const byKey = new Map<string, DblpPaper>();
  for (let i = 0; i < QUERIES.length; i++) {
    const q = QUERIES[i];
    if (i > 0) await sleep(QUERY_DELAY_MS);
    if (VERBOSE) console.error(`  query: "${q}"`);
    const papers = await fetchDblp(q);
    if (papers === null) {
      summary.queries_failed.push(q);
      summary.errors.push(`DBLP query failed: "${q}"`);
      continue;
    }
    summary.queries_run.push(q);
    let added = 0;
    for (const p of papers) {
      if (!byKey.has(p.dblp_key)) {
        byKey.set(p.dblp_key, p);
        added++;
      }
    }
    if (VERBOSE) console.error(`    "${q}": ${papers.length} hits (+${added} new)`);
  }
  if (byKey.size > 0) summary.data_source_used = "DBLP search/publ API";
  return [...byKey.values()];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    queries_run: [],
    queries_failed: [],
    hits_seen: 0,
    recent_filtered_out: 0,
    relevance_filtered_out: 0,
    in_scope: 0,
    top_venue_hits: 0,
    skipped_existing: 0,
    new_proposals: 0,
    data_source_used: null,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-dblp.ts (top-venue academic radar) ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"} | limit: ${LIMIT}`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const papers = await gatherPapers(summary);
  summary.hits_seen = papers.length;

  // No data path: every query failed / empty → recoverable exit 2.
  if (papers.length === 0) {
    summary.errors.push(
      "No data path available: every DBLP query returned non-200, timed out, " +
        "or parsed to 0 hits. Recoverable -- DBLP is occasionally rate-limited " +
        "or under maintenance; retry later or check network.",
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::dblp-summary::${JSON.stringify({
        new_proposals: 0,
        hits_seen: 0,
        in_scope: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const p of papers) {
    // Gate (a): recency.
    if (!RECENT_YEARS.has(p.year)) {
      summary.recent_filtered_out += 1;
      if (VERBOSE)
        console.error(`  filter-out ${p.dblp_key}: year ${p.year || "?"} not recent :: ${p.title}`);
      continue;
    }
    // Gate (b): agent/LLM-attack relevance (title-only).
    const rel = securityRelevance(p.title);
    if (!rel.relevant) {
      summary.relevance_filtered_out += 1;
      if (VERBOSE)
        console.error(`  filter-out ${p.dblp_key}: ${rel.reason} :: ${p.title}`);
      continue;
    }
    summary.in_scope += 1;
    if (p.top_venue) summary.top_venue_hits += 1;
    if (VERBOSE)
      console.error(
        `  in-scope ${p.dblp_key} [${rel.reason}]${p.top_venue ? ` {${p.top_venue}}` : ""}: ${p.title}`,
      );

    if (writtenCount >= LIMIT) continue;

    // Dedup: DBLP id/key, DOI, or normalized title (catches arXiv overlap).
    const id = stableId(p);
    const normTitle = normalizeTitle(p.title);
    if (!FORCE) {
      if (known.ids.has(id) || known.ids.has(p.dblp_key)) {
        summary.skipped_existing += 1;
        if (VERBOSE) console.error(`    skip ${p.dblp_key}: id/key already covered`);
        continue;
      }
      if (p.doi && known.dois.has(p.doi.toLowerCase())) {
        summary.skipped_existing += 1;
        if (VERBOSE) console.error(`    skip ${p.dblp_key}: DOI already covered`);
        continue;
      }
      if (normTitle.length >= 8 && known.titles.has(normTitle)) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`    skip ${p.dblp_key}: title already tracked (e.g. arXiv overlap)`);
        continue;
      }
    }

    const outName = `${id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`    have-proposal ${outName}`);
      continue;
    }

    const body = renderProposal(p);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName} (${p.dblp_key})`);
    } else {
      console.error(`  would write ${outName} (${p.dblp_key})`);
    }
    // Mark as known within this run so two queries returning the same paper
    // under different keys don't both emit.
    known.ids.add(id);
    if (p.doi) known.dois.add(p.doi.toLowerCase());
    if (normTitle.length >= 8) known.titles.add(normTitle);

    summary.new_proposals += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::dblp-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      hits_seen: summary.hits_seen,
      in_scope: summary.in_scope,
      top_venue_hits: summary.top_venue_hits,
      recent_filtered_out: summary.recent_filtered_out,
      relevance_filtered_out: summary.relevance_filtered_out,
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
