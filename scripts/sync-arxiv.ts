#!/usr/bin/env npx tsx
/**
 * sync-arxiv.ts
 *
 * Pulls arXiv cs.CR (+ cs.AI) preprints and emits ATR rule proposals under
 * proposals/arxiv/ARXIV-<arxiv-id>.proposal.yaml.
 *
 * WHY ARXIV IS A DIFFERENT KIND OF SOURCE
 * ---------------------------------------
 * GHSA / Huntr / NVD are CVE sources: each entry is a confirmed vuln in a
 * specific package, usually with a CVE id and a reproducer/PoC. arXiv is the
 * ACADEMIC FRONTLINE — new agent/LLM attack *classes* (RAG poisoning, memory
 * poisoning, indirect prompt injection, GUI-agent privacy exfil) show up here
 * months before they get a CVE or a public exploit. So this script is a
 * DISCOVERY / RESEARCH-RADAR source, not a CVE source:
 *
 *   - Papers have NO CVE and NO inline payload. The abstract is conceptual
 *     prose. => every proposal is detection_ready=FALSE by default. These feed
 *     human/LLM triage; they are NOT auto-promotable to rules/ by
 *     promote-detection-ready.ts.
 *   - Proposal id is `ARXIV-<arxiv-id>` (e.g. ARXIV-2606.12737). No CVE.
 *   - The title + abstract go into `_arxiv_sync.advisory_body` so a future
 *     reviewer / generator has the conceptual description. Any github.com link
 *     found in the abstract is recorded in `_arxiv_sync.code_repo` — that repo
 *     is where a future PoC extraction would happen.
 *
 * DATA SOURCES (attempted in order, RSS preferred)
 * ------------------------------------------------
 *   PRIMARY  RSS daily driver: https://rss.arxiv.org/rss/cs.CR (and cs.CR+cs.AI
 *            via the multi-category feed). Rebuilt daily ~04:00 UTC, ~37
 *            items/day. Each <item> carries title, description (= abstract),
 *            link (arXiv abs URL with the id), guid, category, dc:creator
 *            (authors), pubDate. No auth, no rate limit issues.
 *
 *   BACKFILL arXiv API keyword search:
 *            https://export.arxiv.org/api/query?search_query=cat:cs.CR+AND+all:"prompt injection"&...
 *            Atom XML, HTTPS required, rate-limited on cloud IPs (space >=3s,
 *            expect 429s). Used only with --backfill to widen the net for a
 *            specific keyword. RSS is the default because it never rate-limits.
 *
 * STRICT SECURITY FILTER (important — cs.CR is mostly non-LLM crypto/network)
 * --------------------------------------------------------------------------
 * Keep an item only if its title+abstract contains BOTH:
 *   (a) an LLM/agent term (LLM, agent, MCP, RAG, tool-calling, multi-agent...)
 *   (b) an attack/security term (injection, jailbreak, poisoning, exfiltration,
 *       hijack, adversarial, backdoor...)
 * A few unambiguous phrases ("prompt injection", "indirect prompt injection",
 * "memory poisoning", "RAG poisoning", "tool poisoning", "agent hijack") are
 * accepted on their own because they already encode both halves. This keeps out
 * the crypto/IoT/model-merging-for-CV papers that dominate cs.CR.
 *
 * XML parsing is regex/string extraction — no new dependency (js-yaml is the
 * only import, already used by every other sync-*.ts).
 *
 * Usage:
 *   npx tsx scripts/sync-arxiv.ts                 # dry-run (RSS)
 *   npx tsx scripts/sync-arxiv.ts --write         # write proposals
 *   npx tsx scripts/sync-arxiv.ts --force         # overwrite existing
 *   npx tsx scripts/sync-arxiv.ts --verbose
 *   npx tsx scripts/sync-arxiv.ts --limit 5
 *   npx tsx scripts/sync-arxiv.ts --backfill "indirect prompt injection"
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error)
 *   2 no data path available (recoverable — feed non-200 / timeout / empty)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "arxiv");

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
const BACKFILL = opt("--backfill");

const POLITE_UA =
  "ATR-Sync/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// arXiv RSS daily feeds. cs.CR is the security firehose; the cs.CR+cs.AI feed
// surfaces agentic papers cross-listed to AI. We union both and dedup by id.
const RSS_FEEDS = [
  "https://rss.arxiv.org/rss/cs.CR",
  "https://rss.arxiv.org/rss/cs.CR+cs.AI",
];

const FETCH_TIMEOUT_MS = 30_000;
const BACKFILL_RATE_LIMIT_MS = 3_000; // arXiv API courtesy: >=3s between calls
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Strict agent/LLM security relevance filter.
// ---------------------------------------------------------------------------

// (a) LLM / agent / tool / protocol terms. Bounded so "agent" doesn't match
// "user agent". cs.CR has plenty of network/crypto "agent" noise.
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

// (b) attack / security terms.
const ATTACK_TERMS: RegExp[] = [
  /injection/i,
  /jailbreak/i,
  /poison/i,
  /exfiltrat/i,
  /hijack/i,
  /adversarial/i,
  /backdoor/i,
  /adversarial suffix/i,
  /\battack/i,
  /malicious/i,
  /exploit/i,
  /data leak/i,
  /privacy (exposure|leak)/i,
  /sandbox escape/i,
  /privilege escalation/i,
];

// Unambiguous phrases that already encode BOTH an LLM/agent context AND an
// attack — accepted on their own (they cannot match a non-LLM crypto paper).
const STRONG_PHRASES: RegExp[] = [
  /prompt injection/i,
  /indirect prompt injection/i,
  /\bmemory poisoning/i,
  /\brag poisoning/i,
  /tool poisoning/i,
  /agent hijack/i,
  /\bjailbreak/i, // jailbreak is essentially LLM-only in the cs.CR corpus
];

interface RelevanceResult {
  relevant: boolean;
  reason: string;
}

function securityRelevance(title: string, abstract: string): RelevanceResult {
  const hay = `${title}\n${abstract}`;
  const strong = STRONG_PHRASES.find((rx) => rx.test(hay));
  if (strong) return { relevant: true, reason: `strong phrase /${strong.source}/` };
  const llm = LLM_AGENT_TERMS.find((rx) => rx.test(hay));
  if (!llm)
    return { relevant: false, reason: "no LLM/agent term" };
  const atk = ATTACK_TERMS.find((rx) => rx.test(hay));
  if (!atk)
    return {
      relevant: false,
      reason: `LLM term /${llm.source}/ but no attack term`,
    };
  return {
    relevant: true,
    reason: `LLM /${llm.source}/ + attack /${atk.source}/`,
  };
}

// ---------------------------------------------------------------------------
// Category mapping — best-effort from text (sync-huntr categoryForBounty style).
// These are tracking/research entries; the category is a hint for triage.
// ---------------------------------------------------------------------------

function categoryForPaper(title: string, abstract: string): string {
  const h = `${title} ${abstract}`.toLowerCase();
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
  // arXiv items are conceptual attack research → default to model-abuse
  // (the contract's fallback for unmapped sources).
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// arXiv item model + XML extraction (regex/string only).
// ---------------------------------------------------------------------------

interface ArxivPaper {
  arxiv_id: string; // e.g. "2606.12737" (version stripped)
  title: string;
  abstract: string;
  link: string;
  authors: string[];
  published: string | null; // raw pubDate string from RSS
  categories: string[];
  code_repo: string | null; // first github.com link in the abstract, if any
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function stripTag(raw: string, tag: string): string | null {
  // Handles <tag>..</tag> with optional CDATA and namespaced tags.
  const rx = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const m = raw.match(rx);
  if (!m) return null;
  let v = m[1];
  const cdata = v.match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  if (cdata) v = cdata[1];
  return decodeXmlEntities(v).trim();
}

function allTags(raw: string, tag: string): string[] {
  const rx = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "gi");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = rx.exec(raw)) !== null) {
    out.push(decodeXmlEntities(m[1]).trim());
  }
  return out;
}

// Pull the arXiv id from a link/guid like:
//   https://arxiv.org/abs/2606.12469  ->  2606.12469
//   oai:arXiv.org:2606.12469v1        ->  2606.12469
//   arXiv:2606.12737v1 Announce...     ->  2606.12737
function extractArxivId(...sources: (string | null)[]): string | null {
  for (const s of sources) {
    if (!s) continue;
    const m = s.match(/(\d{4}\.\d{4,5})(v\d+)?/);
    if (m) return m[1];
  }
  return null;
}

// The RSS <description> is "arXiv:ID Announce Type: <t> \nAbstract: <body>".
function extractAbstract(description: string): string {
  const idx = description.search(/Abstract:\s*/i);
  if (idx >= 0) {
    return description.slice(idx).replace(/^Abstract:\s*/i, "").trim();
  }
  // Fallback: drop the leading "arXiv:... Announce Type: ..." preamble.
  return description.replace(/^arXiv:\S+\s+Announce Type:[^\n]*\n?/i, "").trim();
}

// dc:creator is a comma-separated author list, sometimes with parenthetical
// affiliation notes — strip "(...)" and dedup while preserving order.
function parseAuthors(creator: string | null): string[] {
  if (!creator) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of creator.split(",")) {
    const name = part.replace(/\s*\([^)]*\)\s*/g, " ").trim();
    if (name && !seen.has(name)) {
      seen.add(name);
      out.push(name);
    }
  }
  return out;
}

const GITHUB_RX = /https?:\/\/github\.com\/[A-Za-z0-9._\-]+\/[A-Za-z0-9._\-]+/i;

function extractGithub(abstract: string): string | null {
  const m = abstract.match(GITHUB_RX);
  if (!m) return null;
  return m[0].replace(/[).,;]+$/, "");
}

function parseRssItems(xml: string): ArxivPaper[] {
  const items = allTags(xml, "item");
  const papers: ArxivPaper[] = [];
  for (const item of items) {
    const title = stripTag(item, "title") ?? "";
    const link = stripTag(item, "link") ?? "";
    const guid = stripTag(item, "guid") ?? "";
    const description = stripTag(item, "description") ?? "";
    const creator = stripTag(item, "dc:creator");
    const published = stripTag(item, "pubDate");
    const categories = allTags(item, "category");

    const arxivId = extractArxivId(guid, link, description);
    if (!arxivId || !title) continue;

    const abstract = extractAbstract(description);
    papers.push({
      arxiv_id: arxivId,
      title,
      abstract,
      link: link || `https://arxiv.org/abs/${arxivId}`,
      authors: parseAuthors(creator),
      published,
      categories,
      code_repo: extractGithub(abstract),
    });
  }
  return papers;
}

// arXiv API Atom <entry> shape (used by --backfill). Different tag names from
// RSS: <summary> for abstract, <author><name>, <published>, <id> for the URL.
function parseAtomEntries(xml: string): ArxivPaper[] {
  const entries = allTags(xml, "entry");
  const papers: ArxivPaper[] = [];
  for (const e of entries) {
    const title = (stripTag(e, "title") ?? "").replace(/\s+/g, " ").trim();
    const summary = (stripTag(e, "summary") ?? "").replace(/\s+/g, " ").trim();
    const idUrl = stripTag(e, "id") ?? "";
    const published = stripTag(e, "published");
    const arxivId = extractArxivId(idUrl);
    if (!arxivId || !title) continue;
    const authors = allTags(e, "author")
      .map((a) => stripTag(a, "name"))
      .filter((n): n is string => !!n);
    papers.push({
      arxiv_id: arxivId,
      title,
      abstract: summary,
      link: idUrl || `https://arxiv.org/abs/${arxivId}`,
      authors,
      published,
      categories: ["cs.CR"],
      code_repo: extractGithub(summary),
    });
  }
  return papers;
}

// ---------------------------------------------------------------------------
// Fetching.
// ---------------------------------------------------------------------------

async function fetchText(url: string): Promise<string | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(url, {
      headers: { "User-Agent": POLITE_UA, Accept: "application/xml, text/xml, */*" },
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!res.ok) {
      console.error(`non-200 from ${url}: ${res.status} ${res.statusText}`);
      return null;
    }
    return await res.text();
  } catch (e) {
    console.error(`fetch error for ${url}: ${(e as Error).message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Idempotency: index existing arXiv ids / CVEs across rules/ + proposals/.
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
  arxivs: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const arxivs = new Set<string>();
  for (const dir of [RULES_DIR, PROPOSALS_BASE]) {
    for (const f of walkYaml(dir)) {
      // Fast path: filename pattern ARXIV-<id>.proposal.yaml
      const fm = f.match(/ARXIV-(\d{4}\.\d{4,5})/i);
      if (fm) arxivs.add(fm[1]);

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
      // references.arxiv (array or string) and the _arxiv_sync.arxiv_id field.
      const refs = (
        doc as { references?: { arxiv?: string[] | string } }
      )?.references;
      const refArxiv = refs?.arxiv;
      if (typeof refArxiv === "string") {
        const id = extractArxivId(refArxiv);
        if (id) arxivs.add(id);
      } else if (Array.isArray(refArxiv)) {
        for (const a of refArxiv) {
          const id = extractArxivId(typeof a === "string" ? a : null);
          if (id) arxivs.add(id);
        }
      }
      const sync = (doc as { _arxiv_sync?: { arxiv_id?: string } })?._arxiv_sync;
      if (sync?.arxiv_id) {
        const id = extractArxivId(sync.arxiv_id);
        if (id) arxivs.add(id);
      }
    }
  }
  return { arxivs };
}

// ---------------------------------------------------------------------------
// Proposal renderer. Aligned field-for-field with sync-huntr/sync-ghsa, with
// the research-radar specializations (detection_ready always false, no CVE,
// confidence low, subcategory research-radar, advisory_body = title+abstract).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

// Escape a value for embedding inside a YAML *double-quoted* scalar. arXiv
// author names and titles routinely carry LaTeX escapes (e.g. "Pra\c{c}a",
// "B\'ecue"); a bare backslash is an invalid YAML escape sequence, so the
// backslash MUST be doubled before the quote is escaped. (Escaping only the
// quote — as the reference scripts do — breaks js-yaml.load on these names.)
function yq(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see link for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(p: ArxivPaper): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = `ARXIV-${p.arxiv_id}`;
  const category = categoryForPaper(p.title, p.abstract);
  const title = yq(p.title.replace(/\s+/g, " ").slice(0, 120));
  const descOneLine = p.abstract.replace(/\n+/g, " ").trim().slice(0, 600);
  const authorsBlock =
    p.authors.length > 0
      ? p.authors.map((a) => `    - "${yq(a)}"`).join("\n")
      : "    []";

  // Embed title+abstract as YAML-comment lines under detection.conditions so a
  // human reviewer sees the conceptual attack description inline. There is no
  // payload here (it's a paper), so this is context, not an extractable PoC.
  const bodyForComment = `${p.title}\n\n${p.abstract}`;
  const conceptCommentLines = bodyForComment
    .split("\n")
    .filter((s) => s.trim().length > 0)
    .slice(0, 60)
    .map((s) => `    # ${s}`)
    .join("\n");

  return `# ATR rule proposal -- generated by scripts/sync-arxiv.ts
# Source: arXiv preprint ${p.arxiv_id} (cs.CR research radar)
# Imported on: ${today}
# Status: DRAFT -- this is a RESEARCH-RADAR entry, NOT a confirmed vulnerability.
#         A paper has no CVE and no inline payload; the abstract is conceptual.
#         detection_ready is FALSE: this feeds human/LLM triage and is NOT
#         auto-promotable to rules/ by promote-detection-ready.ts. If a PoC is
#         later extracted from the code_repo (if any), a separate detection
#         proposal should be authored.
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  arXiv research-radar entry (${p.arxiv_id}): new agent/LLM attack-class
  preprint. ${descOneLine}
author: "ATR Community (arXiv sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: medium

references:
  arxiv:
    - "${p.arxiv_id}"
  external:
    - "${yq(p.link)}"${p.code_repo ? `\n    - "${yq(p.code_repo)}"` : ""}

metadata_provenance:
  arxiv: arxiv-sync

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
    # TODO(human): this is a research paper, not a confirmed vuln. There is NO
    # extractable payload here. If the attack class proves real and a PoC is
    # published (see code_repo in _arxiv_sync), author a detection proposal
    # from THAT payload — do not regex the abstract prose.
    #
    # === paper title + abstract (conceptual, not a payload) ===
${conceptCommentLines || "    # (no abstract text in source item)"}
    []

response:
  actions:
    - alert
  notify:
    - security_team

confidence: 30

test_cases:
  true_positives: []
  true_negatives: []

# === sync-arxiv.ts provenance ===
_arxiv_sync:
  discovered_by: "arXiv cs.CR RSS via sync-arxiv.ts"
  arxiv_id: "${p.arxiv_id}"
  source: "${yq(p.link)}"
  code_repo: ${p.code_repo ? `"${yq(p.code_repo)}"` : "null"}
  published: ${p.published ? `"${yq(p.published)}"` : "null"}
  categories: ${JSON.stringify(p.categories)}
  authors:
${authorsBlock}
  imported_at: "${new Date().toISOString()}"
  data_source_used: "arXiv RSS cs.CR"
  advisory_body: |
${indentForLiteralBlock(`${p.title}\n\n${p.abstract}`, "    ")}

# Triage flag read by promote-detection-ready.ts. arXiv papers are conceptual:
# no CVE, no inline payload. ALWAYS detection_ready=false — these are
# research-radar entries for human/LLM triage, never auto-promotable to rules.
_triage:
  detection_ready: false
  reason: "arXiv preprint -- conceptual attack research, no CVE / no inline payload (research radar)"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  feeds_fetched: string[];
  items_seen: number;
  in_scope_after_filter: number;
  filtered_out: number;
  skipped_existing: number;
  new_proposals: number;
  with_code_repo: number;
  data_source_used: string | null;
  written_files: string[];
  errors: string[];
}

async function gatherPapers(summary: RunSummary): Promise<ArxivPaper[]> {
  const byId = new Map<string, ArxivPaper>();

  // PRIMARY: RSS feeds (union, dedup by id).
  for (const feed of RSS_FEEDS) {
    const xml = await fetchText(feed);
    if (!xml) {
      summary.errors.push(`RSS fetch failed: ${feed}`);
      continue;
    }
    const parsed = parseRssItems(xml);
    if (parsed.length === 0) {
      summary.errors.push(`RSS parsed 0 items: ${feed}`);
      continue;
    }
    summary.feeds_fetched.push(feed);
    for (const p of parsed) if (!byId.has(p.arxiv_id)) byId.set(p.arxiv_id, p);
    if (VERBOSE) console.error(`  RSS ${feed}: ${parsed.length} items`);
  }

  // BACKFILL: keyword search via the arXiv API (Atom), opt-in only.
  if (BACKFILL) {
    const q = encodeURIComponent(`cat:cs.CR AND all:"${BACKFILL}"`);
    const apiUrl =
      `https://export.arxiv.org/api/query?search_query=${q}` +
      `&sortBy=submittedDate&sortOrder=descending&max_results=50`;
    if (VERBOSE) console.error(`  backfill query: ${apiUrl}`);
    await sleep(BACKFILL_RATE_LIMIT_MS);
    const xml = await fetchText(apiUrl);
    if (xml) {
      const parsed = parseAtomEntries(xml);
      summary.feeds_fetched.push(`api:"${BACKFILL}"`);
      for (const p of parsed) if (!byId.has(p.arxiv_id)) byId.set(p.arxiv_id, p);
      if (VERBOSE) console.error(`  backfill: ${parsed.length} entries`);
    } else {
      summary.errors.push(`backfill API fetch failed for "${BACKFILL}"`);
    }
  }

  if (byId.size > 0) summary.data_source_used = "arXiv RSS cs.CR";
  return [...byId.values()];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    feeds_fetched: [],
    items_seen: 0,
    in_scope_after_filter: 0,
    filtered_out: 0,
    skipped_existing: 0,
    new_proposals: 0,
    with_code_repo: 0,
    data_source_used: null,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-arxiv.ts (research radar) ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const papers = await gatherPapers(summary);
  summary.items_seen = papers.length;

  // No data path: every feed failed / empty → recoverable exit 2.
  if (papers.length === 0) {
    summary.errors.push(
      "No data path available: arXiv RSS feeds returned non-200, timed out, " +
        "or parsed to 0 items. Recoverable — the daily feed rebuilds ~04:00 " +
        "UTC; retry later or check network.",
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::arxiv-summary::${JSON.stringify({
        new_proposals: 0,
        items_seen: 0,
        in_scope_after_filter: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const p of papers) {
    const rel = securityRelevance(p.title, p.abstract);
    if (!rel.relevant) {
      summary.filtered_out += 1;
      if (VERBOSE)
        console.error(`  filter-out ${p.arxiv_id}: ${rel.reason} :: ${p.title}`);
      continue;
    }
    summary.in_scope_after_filter += 1;
    if (VERBOSE)
      console.error(`  in-scope ${p.arxiv_id} [${rel.reason}]: ${p.title}`);

    if (writtenCount >= LIMIT) continue;

    if (!FORCE && known.arxivs.has(p.arxiv_id)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`    skip ${p.arxiv_id}: already covered`);
      continue;
    }
    const outName = `ARXIV-${p.arxiv_id}.proposal.yaml`;
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
      console.error(`  wrote ${outName}`);
    } else {
      console.error(`  would write ${outName}`);
    }
    if (p.code_repo) summary.with_code_repo += 1;
    summary.new_proposals += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::arxiv-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      items_seen: summary.items_seen,
      in_scope_after_filter: summary.in_scope_after_filter,
      filtered_out: summary.filtered_out,
      skipped_existing: summary.skipped_existing,
      with_code_repo: summary.with_code_repo,
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
