#!/usr/bin/env npx tsx
/**
 * sync-certcc.ts
 *
 * Pulls CERT/CC Vulnerability Notes (CMU SEI) for AI / agent / LLM / MCP
 * relevant issues and emits ATR rule proposals under
 * proposals/certcc/<CVE-or-VU-id>.proposal.yaml.
 *
 * Why CERT/CC: it is a LOW-volume source (tens of notes per year) but each
 * note is a deep coordinated-disclosure narrative — multi-vendor impact,
 * full Overview/Description/Impact/Solution prose, and reporter
 * acknowledgements — that NVD's terse one-liners lack. The value is the
 * narrative body, which we capture verbatim into `_certcc_sync.advisory_body`
 * for a human reviewer (and promote-detection-ready.ts) to convert into
 * precision-safe detection.conditions.
 *
 * Data source (no auth required):
 *   1. Atom feed: https://www.kb.cert.org/vuls/atomfeed/
 *      "CERT Recently Published Vulnerability Notes". Contains every recent
 *      note with title (VU#id + name), link, published/updated timestamps,
 *      and an HTML <summary>/<content> body. We parse the WHOLE feed (volume
 *      is low) with regex/string extraction — no XML dependency added.
 *   2. Per-note JSON: https://kb.cert.org/vuls/api/<id>/  (id = the digits in
 *      VU#<id>). Gives clean markdown `overview` (the full body), `impact`,
 *      `resolution`, `public` (reference URLs), and `cveids` (array — a single
 *      note can map to MANY CVEs, e.g. VU#777338 SGLang → 3 CVEs). We fetch
 *      JSON only for notes that pass the agent-relevance gate.
 *
 * Scope discipline (shared with sync-ghsa.ts): ATR detects AGENT-runtime
 * threats (prompt injection / tool·MCP poisoning / context exfiltration /
 * excessive autonomy). CERT/CC covers ALL of computing (bootloaders, kernel
 * drivers, dnsmasq, TLS libs ...), so the agent-relevance gate is essential —
 * we keep only notes whose title/body carry an agent-threat signal. CERT/CC
 * notes carry NO CWE field, so the gate relies on the keyword signal
 * (AGENT_THREAT_KEYWORDS, reused from sync-ghsa.ts's design) and category is
 * derived from the body, falling back to "model-abuse".
 *
 * Detection-readiness: CERT/CC bodies are almost always PROSE (coordinated
 * disclosure narratives), not payloads, so detection_ready is usually false.
 * It is set true only when the body contains payload-like content (fenced
 * code block, explicit payload/command string, PoC reference link).
 *
 * Idempotency: skip a note if ANY of its CVE ids — or its VU# id — already
 * exists in rules/ or proposals/, unless --force. CVE ID is the cross-source
 * primary key.
 *
 * Secret discipline: NO auth is used or accepted. There is no API key. A
 * non-200 / timeout on the Atom feed (the one required network hop) is a
 * no-data condition → exit 2 (recoverable; the daily cron retries tomorrow).
 *
 * Usage:
 *   npx tsx scripts/sync-certcc.ts                  # dry-run
 *   npx tsx scripts/sync-certcc.ts --write          # write proposals
 *   npx tsx scripts/sync-certcc.ts --force          # overwrite existing
 *   npx tsx scripts/sync-certcc.ts --limit 5 --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error)
 *   2 no data path available (Atom feed unreachable / empty)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "certcc");

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

const ATOM_FEED_URL = "https://www.kb.cert.org/vuls/atomfeed/";
const NOTE_JSON_URL = (id: string) => `https://kb.cert.org/vuls/api/${id}/`;
const NOTE_HTML_URL = (id: string) => `https://kb.cert.org/vuls/id/${id}`;
const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";
const FETCH_TIMEOUT_MS = 30_000;
// CERT/CC is low volume and unauthenticated; a polite gap between per-note
// JSON fetches keeps us a good citizen.
const RATE_LIMIT_MS = 500;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchText(url: string): Promise<{ ok: boolean; status: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": POLITE_UA, Accept: "*/*" },
      signal: controller.signal,
    });
    const body = await res.text();
    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Agent-relevance gate (design mirrors sync-ghsa.ts agentRelevance). CERT/CC
// notes carry no CWE, so we rely entirely on the keyword signal against the
// title + body. "agent" alone is intentionally NOT a keyword (it false-matches
// "user agent"); we require a specific agent/LLM/MCP phrase or an injection /
// exec / exfil signal.
// ---------------------------------------------------------------------------

const AGENT_THREAT_KEYWORDS: RegExp[] = [
  /prompt injection/,
  /prompt-injection/,
  /system prompt/,
  /jailbreak/,
  /\bllm\b/,
  /large language model/,
  /\bgpt\b/,
  /\bgguf\b/,
  /\bollama\b/,
  /\bagentic\b/,
  /\bai[- ]agent/,
  /\bllm[- ]agent/,
  /agent framework/,
  /\bcopilot\b/,
  /tool call/,
  /tool-calling/,
  /tool poisoning/,
  /model context protocol/,
  /\bmcp\b/,
  /retrieval[- ]augmented/,
  /\brag\b/,
  /langchain/,
  /llama[- ]?index/,
  /semantic[- ]kernel/,
  /\bautogen\b/,
  /crew[- ]?ai/,
  /fastmcp/,
  /litellm/,
  /\bsglang\b/,
  /\bvllm\b/,
  /\bquantiz/,
  /model (?:upload|quantization|inference|serving)/,
];

function agentRelevance(text: string): { relevant: boolean; reason: string } {
  const body = text.toLowerCase();
  const hit = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hit) return { relevant: true, reason: `agent-threat keyword /${hit.source}/` };
  return { relevant: false, reason: "no agent/LLM/MCP signal in title or body" };
}

// ---------------------------------------------------------------------------
// Category inference. CERT/CC has no CWE, so we read the body for the same
// signals sync-ghsa.ts's CWE_TO_CATEGORY targets. Fallback per contract:
// "model-abuse".
// ---------------------------------------------------------------------------

function guessCategory(text: string): string {
  const h = text.toLowerCase();
  if (/prompt[- ]injection|jailbreak/.test(h)) return "prompt-injection";
  if (/ssrf|server[- ]side[- ]request[- ]forgery/.test(h)) return "tool-poisoning";
  if (
    /path[- ]traversal|directory[- ]traversal|local[- ]file[- ](read|include)|\blfi\b|arbitrary file (read|write)/.test(
      h,
    )
  )
    return "context-exfiltration";
  if (/info(rmation)?[- ]?(leak|disclos)|memory leak|exfiltrat|sensitive data/.test(h))
    return "context-exfiltration";
  if (/auth(entication)?[- ]bypass|unauthor(i[sz]ed|ised)|access control|privilege escalation/.test(h))
    return "privilege-escalation";
  if (/sql injection/.test(h)) return "data-poisoning";
  if (
    /remote code execution|\brce\b|arbitrary code|code execution|command injection|deserial|pickle|unsafe (reflection|deserial)/.test(
      h,
    )
  )
    return "tool-poisoning";
  if (/cross[- ]site[- ]scripting|\bxss\b/.test(h)) return "context-exfiltration";
  return "model-abuse";
}

// Severity inference (CERT/CC rarely populates cvss/severity). Map from the
// vulnerability wording; default high (CERT/CC only publishes notes for
// meaningful issues).
function guessSeverity(text: string): "critical" | "high" | "medium" | "low" {
  const h = text.toLowerCase();
  if (/remote code execution|\brce\b|arbitrary code|unauthenticated.*(rce|remote code|code execution)/.test(h))
    return "critical";
  if (/code execution|command injection|deserial|privilege escalation|authentication bypass|sql injection/.test(h))
    return "high";
  if (/path[- ]traversal|cross[- ]site[- ]scripting|\bxss\b|information disclosure|memory leak|exfiltrat/.test(h))
    return "high";
  return "high";
}

// ---------------------------------------------------------------------------
// Atom feed parsing — regex/string extraction (no XML dependency).
// ---------------------------------------------------------------------------

interface FeedEntry {
  vuId: string; // "VU#518910"
  noteId: string; // "518910"
  title: string; // human title (without the "VU#id: " prefix)
  noteUrl: string; // https://kb.cert.org/vuls/id/518910
  published: string | null;
  updated: string | null;
  summaryHtml: string; // html body from the feed (fallback if JSON missing)
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

function stripHtml(s: string): string {
  return decodeXmlEntities(s)
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function tagText(block: string, tag: string): string | null {
  // Matches <tag ...>...</tag> (non-greedy). Returns inner text or null.
  const rx = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const m = block.match(rx);
  return m ? m[1] : null;
}

function attr(block: string, tag: string, attrName: string): string | null {
  const rx = new RegExp(`<${tag}[^>]*\\b${attrName}="([^"]*)"[^>]*/?>`, "i");
  const m = block.match(rx);
  return m ? m[1] : null;
}

function parseFeed(xml: string): FeedEntry[] {
  const entries: FeedEntry[] = [];
  const blocks = xml.match(/<entry>[\s\S]*?<\/entry>/g) ?? [];
  for (const block of blocks) {
    const rawTitle = tagText(block, "title");
    if (!rawTitle) continue;
    const titleText = decodeXmlEntities(rawTitle).trim();
    // "VU#518910: Ollama GGUF Quantization Remote Memory Leak"
    const m = titleText.match(/^(VU#(\d+))\s*:?\s*(.*)$/);
    if (!m) continue;
    const vuId = m[1];
    const noteId = m[2];
    const title = (m[3] || titleText).trim();
    // link rel="alternate" href, else <id>
    const linkHref =
      attr(block, "link", "href") || tagText(block, "id") || NOTE_HTML_URL(noteId);
    const summaryHtml = tagText(block, "summary") ?? tagText(block, "content") ?? "";
    entries.push({
      vuId,
      noteId,
      title,
      noteUrl: NOTE_HTML_URL(noteId),
      published: tagText(block, "published"),
      updated: tagText(block, "updated"),
      summaryHtml,
    });
    void linkHref;
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Per-note JSON detail.
// ---------------------------------------------------------------------------

interface NoteDetail {
  vuid?: string;
  idnumber?: string;
  name?: string;
  overview?: string | null;
  impact?: string | null;
  resolution?: string | null;
  workarounds?: string | null;
  public?: string[] | null;
  cveids?: string[] | null;
  publicdate?: string | null;
  datefirstpublished?: string | null;
}

interface NoteFull {
  vuId: string;
  noteId: string;
  title: string;
  noteUrl: string;
  cveIds: string[];
  references: string[];
  body: string; // assembled prose body (overview + impact + resolution)
  published: string | null;
}

function assembleBody(d: NoteDetail, fallbackHtml: string): string {
  const parts: string[] = [];
  if (d.overview) parts.push(d.overview.trim());
  if (d.impact) parts.push(`### Impact\n${d.impact.trim()}`);
  if (d.resolution) parts.push(`### Solution\n${d.resolution.trim()}`);
  if (d.workarounds) parts.push(`### Workarounds\n${d.workarounds.trim()}`);
  const joined = parts.join("\n\n").trim();
  if (joined.length > 0) return joined;
  // JSON gave us nothing usable — fall back to the feed HTML body, stripped.
  return stripHtml(fallbackHtml);
}

async function fetchNoteDetail(entry: FeedEntry): Promise<NoteFull | null> {
  let res: Awaited<ReturnType<typeof fetchText>>;
  try {
    res = await fetchText(NOTE_JSON_URL(entry.noteId));
  } catch (e) {
    if (VERBOSE) console.error(`  json fetch error ${entry.vuId}: ${(e as Error).message}`);
    return null;
  }
  let detail: NoteDetail | null = null;
  if (res.ok) {
    const trimmed = res.body.trim();
    if (trimmed.startsWith("{")) {
      try {
        detail = JSON.parse(trimmed) as NoteDetail;
      } catch {
        detail = null;
      }
    }
  }
  // The API returns HTTP 200 even for non-existent ids, so validate the
  // payload actually describes this note before trusting it.
  const validJson =
    detail && (detail.vuid === entry.vuId || detail.idnumber === entry.noteId);

  const d = validJson ? (detail as NoteDetail) : {};
  const cveIds = Array.isArray(d.cveids)
    ? d.cveids.filter((c): c is string => typeof c === "string" && /^CVE-\d{4}-\d+$/.test(c))
    : [];
  const refs = Array.isArray(d.public)
    ? d.public.filter((r): r is string => typeof r === "string" && r.length > 0)
    : [];
  // Always include the canonical CERT/CC note URL as a reference.
  const references = Array.from(new Set([...refs, entry.noteUrl]));
  const body = assembleBody(d, entry.summaryHtml);

  return {
    vuId: entry.vuId,
    noteId: entry.noteId,
    title: (d.name || entry.title).trim(),
    noteUrl: entry.noteUrl,
    cveIds,
    references,
    body,
    published: d.datefirstpublished || d.publicdate || entry.published,
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE/VU ids across rules/ and proposals/.
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
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml"))) out.push(f);
  }
  return out;
}

interface KnownIndex {
  cves: Set<string>;
  vus: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const vus = new Set<string>();
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
          references?: { cve?: string[]; certcc?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.certcc) {
        const v = refs.certcc;
        if (typeof v === "string") vus.add(v);
        else if (Array.isArray(v))
          for (const h of v) if (typeof h === "string") vus.add(h);
      }
      // Also pick up VU# ids appearing anywhere in the raw text (filename or
      // provenance block) so a note is never re-proposed under either key.
      for (const m of raw.matchAll(/VU#\d{6,}/g)) vus.add(m[0]);
    }
  }
  return { cves, vus };
}

// ---------------------------------------------------------------------------
// Detection-readiness triage.
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
    "\\$\\{[^}]+\\}", // template-injection style
  ].join("|"),
  "im",
);

function isDetectionReady(note: NoteFull): { ready: boolean; reason: string } {
  if (PAYLOAD_HEURISTICS_RX.test(note.body))
    return { ready: true, reason: "payload-like content in note body" };
  if (note.references.some((r) => /poc|exploit-db|exploit\b/i.test(r)))
    return { ready: true, reason: "PoC reference link present" };
  return {
    ready: false,
    reason: "coordinated-disclosure prose only; no reproducer / payload section",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer (fields & order aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see note URL for full text)`
      : text;
  return capped
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(note: NoteFull): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = note.cveIds[0] ?? note.vuId.replace("#", "-"); // VU-518910
  const category = guessCategory(`${note.title}\n${note.body}`);
  const severity = guessSeverity(`${note.title}\n${note.body}`);
  const triage = isDetectionReady(note);
  const responseActions =
    severity === "critical" || severity === "high" ? ["block_input", "alert"] : ["alert"];

  const cveBlock =
    note.cveIds.length > 0
      ? `  cve:\n${note.cveIds.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const certccBlock = `  certcc:\n    - "${note.vuId}"\n`;
  const externalBlock =
    note.references.length > 0
      ? `  external:\n${note.references.map((u) => `    - "${u}"`).join("\n")}\n`
      : `  external:\n    - "${note.noteUrl}"\n`;

  const title = note.title.replace(/"/g, '\\"').slice(0, 120);
  const descOneLine = note.body.replace(/\r?\n+/g, " ").replace(/\s+/g, " ").trim();

  // Embed the note body as YAML comment lines under detection.conditions so a
  // reviewer has the attack narrative inline when writing matchers.
  const bodyCommentLines =
    note.body
      .replace(/\r\n/g, "\n")
      .split("\n")
      .filter((s) => s.trim().length > 0)
      .slice(0, 60)
      .map((s) => `    # ${s}`)
      .join("\n") || "    # (no body text available)";

  return `# ATR rule proposal -- generated by scripts/sync-certcc.ts
# Source: CERT/CC Vulnerability Note ${note.vuId}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The CERT/CC note body
#         is attached as a YAML comment under detection.conditions and in full
#         under _certcc_sync.advisory_body for conversion to a precision-safe
#         regex.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  CERT/CC Vulnerability Note ${note.vuId}${
    note.cveIds.length ? ` (${note.cveIds.join(", ")})` : ""
  }.
  ${descOneLine.slice(0, 600)}
author: "ATR Community (CERT/CC sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${certccBlock}${externalBlock}
metadata_provenance:
  certcc: certcc-sync
${note.cveIds.length ? "  cve: certcc-sync\n" : ""}
tags:
  category: ${category}
  subcategory: certcc-imported
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
    # TODO(human): convert the CERT/CC note narrative below into
    # precision-safe detection.conditions regex/string matchers. Empty until
    # promoted to rules/. Full body is also under _certcc_sync.advisory_body.
    #
    # === CERT/CC note body excerpt ===
${bodyCommentLines}
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

# === sync-certcc.ts provenance ===
_certcc_sync:
  vu_id: "${note.vuId}"
  note_id: "${note.noteId}"
  note_url: "${note.noteUrl}"
  cve_ids: ${JSON.stringify(note.cveIds)}
  references: ${JSON.stringify(note.references)}
  published: ${note.published ? `"${note.published}"` : "null"}
  data_source_used: "CERT/CC Atom feed + per-note JSON"
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(note.body || "(no body text available)", "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  feed_entries: number;
  agent_relevant: number;
  filtered_not_agent: number;
  json_fetch_failures: number;
  skipped_existing: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  written_files: string[];
  errors: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    feed_entries: 0,
    agent_relevant: 0,
    filtered_not_agent: 0,
    json_fetch_failures: 0,
    skipped_existing: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-certcc.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  if (WRITE && !existsSync(PROPOSALS_DIR)) mkdirSync(PROPOSALS_DIR, { recursive: true });

  // --- fetch the Atom feed (the one required network hop) ---
  let feedRes: Awaited<ReturnType<typeof fetchText>>;
  try {
    feedRes = await fetchText(ATOM_FEED_URL);
  } catch (e) {
    summary.errors.push(`Atom feed fetch failed: ${(e as Error).message}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(`::certcc-summary::${JSON.stringify({ new_proposals: 0, error: "feed_unreachable" })}`);
    process.exit(2);
  }
  if (!feedRes.ok) {
    summary.errors.push(`Atom feed returned HTTP ${feedRes.status}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::certcc-summary::${JSON.stringify({ new_proposals: 0, error: `feed_http_${feedRes.status}` })}`,
    );
    process.exit(2);
  }

  const entries = parseFeed(feedRes.body);
  summary.feed_entries = entries.length;
  console.error(`Atom feed: ${entries.length} notes`);
  if (entries.length === 0) {
    summary.errors.push("Atom feed parsed to 0 entries (shape may have changed)");
    console.log(JSON.stringify(summary, null, 2));
    console.log(`::certcc-summary::${JSON.stringify({ new_proposals: 0, error: "no_entries" })}`);
    process.exit(2);
  }

  // --- agent-relevance filter on title + feed summary (before JSON fetch) ---
  const inScope: FeedEntry[] = [];
  for (const e of entries) {
    const text = `${e.title}\n${stripHtml(e.summaryHtml)}`;
    const rel = agentRelevance(text);
    if (rel.relevant) {
      summary.agent_relevant += 1;
      inScope.push(e);
      if (VERBOSE) console.error(`  in-scope ${e.vuId}: ${rel.reason}`);
    } else {
      summary.filtered_not_agent += 1;
      if (VERBOSE) console.error(`  drop ${e.vuId}: ${rel.reason}`);
    }
  }
  console.error(`agent-relevant: ${inScope.length} / ${entries.length}`);

  // --- fetch JSON detail + write proposals for in-scope notes ---
  const known = buildKnownIndex();
  let writtenCount = 0;
  let sampleShown = false;

  for (const e of inScope) {
    if (writtenCount >= LIMIT) break;

    const note = await fetchNoteDetail(e);
    await sleep(RATE_LIMIT_MS);
    if (!note) {
      summary.json_fetch_failures += 1;
      summary.errors.push(`json detail failed for ${e.vuId}`);
      continue;
    }

    // Dedup: any CVE id OR the VU# id already covered → skip.
    const cveHit = note.cveIds.find((c) => known.cves.has(c));
    if (!FORCE && cveHit) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-rule ${cveHit} (${note.vuId}): already covered`);
      continue;
    }
    if (!FORCE && known.vus.has(note.vuId)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-rule ${note.vuId}: already covered`);
      continue;
    }

    const outName = `${note.cveIds[0] ?? note.vuId.replace("#", "-")}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    const triage = isDetectionReady(note);
    const body = renderProposal(note);

    // Dry-run self-validation: parse the first rendered proposal to prove it's
    // valid YAML before any write happens.
    if (!sampleShown) {
      try {
        yaml.load(body);
        console.error(`  [self-check] sample proposal ${outName} parses as valid YAML`);
      } catch (err) {
        summary.errors.push(`sample proposal ${outName} failed yaml.load: ${(err as Error).message}`);
        console.error(`  [self-check] FAILED to parse ${outName}: ${(err as Error).message}`);
      }
      sampleShown = true;
    }

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName} (cve=${note.cveIds.join(",") || "none"})`);
    } else {
      console.error(`  would write ${outName} (cve=${note.cveIds.join(",") || "none"})`);
    }

    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::certcc-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      feed_entries: summary.feed_entries,
      agent_relevant: summary.agent_relevant,
      filtered_not_agent: summary.filtered_not_agent,
      skipped_existing: summary.skipped_existing,
      json_fetch_failures: summary.json_fetch_failures,
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
