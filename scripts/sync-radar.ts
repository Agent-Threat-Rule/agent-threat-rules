#!/usr/bin/env npx tsx
/**
 * sync-radar.ts
 *
 * EARLY-WARNING RADAR COLLECTOR -- NOT a rule-proposal source.
 *
 * Unlike sync-ghsa / sync-huntr / sync-arxiv, this script does NOT emit ATR
 * rule proposals. It collects agent/LLM/MCP-security *signal* from high-value
 * blogs and link aggregators into a single dated digest JSON for human + LLM
 * triage. An item that points at a real PoC becomes a MANUAL rule candidate;
 * nothing here is auto-promotable.
 *
 * Output (single file per run, idempotent for the day):
 *   data/radar/radar-YYYY-MM-DD.json
 *   data/radar/latest.json            (copy of the most recent digest)
 *
 * Digest shape:
 *   {
 *     generated_at: ISO8601,
 *     run_date: "YYYY-MM-DD",
 *     sources_polled: [{ source, ok, items_raw, items_relevant, error? }],
 *     items: [{ source, title, url, date, snippet, matched_keywords }]
 *   }
 *
 * SOURCES (all RSS / JSON, no auth)
 * ---------------------------------
 *   - Hacker News via Algolia search_by_date (JSON). Rotated queries: MCP,
 *     "prompt injection", "LLM agent", "AI agent RCE", jailbreak. Algolia's
 *     match is fuzzy (a "MCP" query also returns "MVP"), so EVERY hit is run
 *     through the same keyword gate as the feed items. Filtered to last 7 days.
 *   - Embrace The Red (Johann Rehberger) -- RSS index.xml
 *   - Simon Willison prompt-injection tag -- Atom
 *   - Zero Day Initiative blog -- RSS (Pwn2Own agent results)
 *   - lobste.rs security tag -- JSON (title-gated to AI/LLM/MCP)
 *
 * RELEVANCE GATE
 * --------------
 * Item kept if title+snippet matches an agent/LLM/MCP-security keyword. Some
 * sources are already topical (Embrace The Red, Simon Willison's PI tag) so
 * their items pass with a low bar; broad sources (HN, lobste.rs, ZDI) need a
 * harder match. Matched keywords are recorded per item so triage can sort.
 *
 * XML parsing is regex/string extraction (same approach as sync-arxiv) -- the
 * only npm import is for fs/path; no new dependency.
 *
 * Usage:
 *   npx tsx scripts/sync-radar.ts            # dry-run: report counts, write nothing
 *   npx tsx scripts/sync-radar.ts --write    # write data/radar/radar-<date>.json + latest.json
 *   npx tsx scripts/sync-radar.ts --verbose
 *   npx tsx scripts/sync-radar.ts --limit 20 # cap items in the digest
 *
 * Summary marker (last line):
 *   ::radar-summary::{sources_polled, items_total, items_relevant, new_since_last}
 *
 * Exit codes:
 *   0 success (at least one source polled OK)
 *   1 fatal (unexpected error)
 *   2 no data path (every source failed -- recoverable, retry later)
 *
 * SECRET DISCIPLINE: none of these sources need auth. This script reads no
 * secrets, accepts no --key arg, and echoes nothing sensitive.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RADAR_DIR = resolve(REPO_ROOT, "data", "radar");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const VERBOSE = flag("--verbose");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;

const POLITE_UA =
  "ATR-Radar/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules)";

const FETCH_TIMEOUT_MS = 30_000;
const WINDOW_DAYS = 7;
const WINDOW_MS = WINDOW_DAYS * 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Relevance gate. An item is kept if it matches any of these agent/LLM/MCP
// security keywords. The matched ones are recorded for triage sorting.
// ---------------------------------------------------------------------------

const KEYWORDS: { rx: RegExp; label: string }[] = [
  { rx: /\bmcp\b/i, label: "mcp" },
  { rx: /model context protocol/i, label: "model-context-protocol" },
  { rx: /prompt injection/i, label: "prompt-injection" },
  { rx: /indirect prompt injection/i, label: "indirect-prompt-injection" },
  { rx: /jailbreak/i, label: "jailbreak" },
  { rx: /\bllm\b/i, label: "llm" },
  { rx: /large language model/i, label: "llm" },
  { rx: /\bai agent/i, label: "ai-agent" },
  { rx: /\bllm agent/i, label: "llm-agent" },
  { rx: /agentic/i, label: "agentic" },
  { rx: /\bagent\b.*\b(rce|exploit|attack|hijack|takeover)/i, label: "agent-exploit" },
  { rx: /tool poisoning/i, label: "tool-poisoning" },
  { rx: /tool[- ]description/i, label: "tool-description" },
  { rx: /memory poisoning/i, label: "memory-poisoning" },
  { rx: /rag poisoning/i, label: "rag-poisoning" },
  { rx: /context (exfiltrat|leak)/i, label: "context-exfiltration" },
  { rx: /data exfiltrat/i, label: "data-exfiltration" },
  { rx: /\bclaude\b/i, label: "claude" },
  { rx: /\bcopilot\b/i, label: "copilot" },
  { rx: /\bcursor\b/i, label: "cursor" },
  { rx: /\bchatgpt\b/i, label: "chatgpt" },
  { rx: /system prompt (leak|extract|disclos)/i, label: "system-prompt-leak" },
  { rx: /\bgpt-?\d/i, label: "gpt" },
];

function matchKeywords(text: string): string[] {
  const out = new Set<string>();
  for (const { rx, label } of KEYWORDS) {
    if (rx.test(text)) out.add(label);
  }
  return [...out];
}

// ---------------------------------------------------------------------------
// Shared item model.
// ---------------------------------------------------------------------------

interface RadarItem {
  source: string;
  title: string;
  url: string;
  date: string | null; // ISO date when derivable
  snippet: string;
  matched_keywords: string[];
}

interface SourceResult {
  source: string;
  ok: boolean;
  items_raw: number;
  items_relevant: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// Fetch helpers.
// ---------------------------------------------------------------------------

async function fetchText(url: string): Promise<string> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": POLITE_UA,
        Accept: "application/json, application/xml, text/xml, */*",
      },
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

// ---------------------------------------------------------------------------
// XML / text utilities (regex extraction, same idea as sync-arxiv).
// ---------------------------------------------------------------------------

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, "/")
    .replace(/&amp;/g, "&");
}

function stripHtml(s: string): string {
  return decodeXmlEntities(s.replace(/<[^>]+>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

function stripTag(raw: string, tag: string): string | null {
  const rx = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const m = raw.match(rx);
  if (!m) return null;
  let v = m[1];
  const cdata = v.match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  if (cdata) v = cdata[1];
  return decodeXmlEntities(v).trim();
}

function allBlocks(raw: string, tag: string): string[] {
  const rx = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "gi");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = rx.exec(raw)) !== null) out.push(m[1]);
  return out;
}

// Atom <link href="..."/> (Simon Willison) vs RSS <link>...</link>.
function extractLink(block: string): string {
  const inline = stripTag(block, "link");
  if (inline && /^https?:/i.test(inline)) return inline;
  const href = block.match(/<link[^>]*\bhref=["']([^"']+)["']/i);
  return href ? href[1] : "";
}

function toIsoDate(raw: string | null): string | null {
  if (!raw) return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

// Recency gate. Full feeds (Embrace The Red ships its entire archive, Simon
// Willison's PI tag spans years) would otherwise flood the digest with old
// posts. Keep items inside the WINDOW_DAYS window. Undated items are kept --
// better a false keep than dropping a fresh post with a malformed date.
function withinWindow(rawDate: string | null): boolean {
  if (!rawDate) return true;
  const t = new Date(rawDate).getTime();
  if (isNaN(t)) return true;
  return t >= Date.now() - WINDOW_MS;
}

function snippetOf(s: string, max = 280): string {
  const clean = stripHtml(s);
  return clean.length > max ? clean.slice(0, max).trimEnd() + "..." : clean;
}

// ---------------------------------------------------------------------------
// Source collectors. Each returns RadarItem[] (already keyword-gated) and is
// wrapped so a single failure never sinks the run.
// ---------------------------------------------------------------------------

const HN_QUERIES = [
  "MCP",
  "prompt injection",
  "LLM agent",
  "AI agent RCE",
  "jailbreak",
];

async function collectHackerNews(res: SourceResult): Promise<RadarItem[]> {
  const cutoff = Date.now() - WINDOW_MS;
  const byUrl = new Map<string, RadarItem>();
  let raw = 0;
  for (const q of HN_QUERIES) {
    const url =
      `https://hn.algolia.com/api/v1/search_by_date?query=${encodeURIComponent(q)}` +
      `&tags=story&hitsPerPage=50`;
    const text = await fetchText(url);
    const json = JSON.parse(text) as {
      hits?: {
        title?: string;
        url?: string;
        story_text?: string | null;
        objectID?: string;
        created_at?: string;
        created_at_i?: number;
      }[];
    };
    const hits = json.hits ?? [];
    for (const h of hits) {
      raw += 1;
      const createdMs = h.created_at_i
        ? h.created_at_i * 1000
        : h.created_at
          ? new Date(h.created_at).getTime()
          : 0;
      if (!createdMs || createdMs < cutoff) continue; // last 7 days only
      const title = (h.title ?? "").trim();
      if (!title) continue;
      const itemUrl =
        h.url ?? `https://news.ycombinator.com/item?id=${h.objectID ?? ""}`;
      const snippet = snippetOf(h.story_text ?? "");
      // Algolia match is fuzzy -> apply the real keyword gate ourselves.
      const matched = matchKeywords(`${title} ${snippet}`);
      if (matched.length === 0) continue;
      const key = normalizeUrl(itemUrl);
      if (!byUrl.has(key)) {
        byUrl.set(key, {
          source: "hackernews",
          title,
          url: itemUrl,
          date: toIsoDate(h.created_at ?? null),
          snippet,
          matched_keywords: matched,
        });
      }
    }
  }
  res.items_raw = raw;
  return [...byUrl.values()];
}

// RSS / Atom blog collector. `topical` lowers the bar: the source is already
// on-topic (Embrace The Red, Simon Willison PI tag), so items with no explicit
// keyword still pass, tagged with a synthetic source-topic keyword.
async function collectFeed(
  res: SourceResult,
  feedUrl: string,
  source: string,
  topical: boolean,
  topicLabel: string,
): Promise<RadarItem[]> {
  const text = await fetchText(feedUrl);
  // RSS uses <item>, Atom uses <entry>.
  const blocks = text.includes("<entry")
    ? allBlocks(text, "entry")
    : allBlocks(text, "item");
  res.items_raw = blocks.length;
  const out: RadarItem[] = [];
  for (const b of blocks) {
    const title = (stripTag(b, "title") ?? "").replace(/\s+/g, " ").trim();
    if (!title) continue;
    const url = extractLink(b);
    const body =
      stripTag(b, "content:encoded") ??
      stripTag(b, "summary") ??
      stripTag(b, "description") ??
      stripTag(b, "content") ??
      "";
    const rawDate =
      stripTag(b, "pubDate") ??
      stripTag(b, "published") ??
      stripTag(b, "updated");
    if (!withinWindow(rawDate)) continue; // last 7 days only
    const date = toIsoDate(rawDate);
    const snippet = snippetOf(body);
    let matched = matchKeywords(`${title} ${snippet}`);
    if (matched.length === 0) {
      if (!topical) continue;
      matched = [topicLabel]; // source itself is the topic signal
    }
    out.push({ source, title, url, date, snippet, matched_keywords: matched });
  }
  return out;
}

async function collectLobsters(res: SourceResult): Promise<RadarItem[]> {
  const text = await fetchText("https://lobste.rs/t/security.json");
  const json = JSON.parse(text) as {
    short_id?: string;
    title?: string;
    url?: string;
    short_id_url?: string;
    created_at?: string;
    description_plain?: string;
    tags?: string[];
  }[];
  res.items_raw = json.length;
  const out: RadarItem[] = [];
  for (const s of json) {
    const title = (s.title ?? "").trim();
    if (!title) continue;
    if (!withinWindow(s.created_at ?? null)) continue; // last 7 days only
    const snippet = snippetOf(s.description_plain ?? "");
    const matched = matchKeywords(`${title} ${snippet}`);
    if (matched.length === 0) continue; // hard gate: lobste.rs/security is broad
    out.push({
      source: "lobsters",
      title,
      url: s.url || s.short_id_url || "",
      date: toIsoDate(s.created_at ?? null),
      snippet,
      matched_keywords: matched,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Dedup against the previous digest (normalized url, fallback normalized title).
// ---------------------------------------------------------------------------

function normalizeUrl(u: string): string {
  if (!u) return "";
  try {
    const url = new URL(u);
    url.hash = "";
    url.search = "";
    let s = `${url.host}${url.pathname}`.toLowerCase();
    s = s.replace(/\/+$/, "");
    return s;
  } catch {
    return u.trim().toLowerCase();
  }
}

function normalizeTitle(t: string): string {
  return t.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function itemKey(it: RadarItem): string {
  const nu = normalizeUrl(it.url);
  return nu || `title:${normalizeTitle(it.title)}`;
}

// Read the most recent prior digest (any radar-*.json that is not today's).
function loadPreviousKeys(todayFile: string): Set<string> {
  const keys = new Set<string>();
  if (!existsSync(RADAR_DIR)) return keys;
  const files = readdirSync(RADAR_DIR)
    .filter((f) => /^radar-\d{4}-\d{2}-\d{2}\.json$/.test(f))
    .filter((f) => join(RADAR_DIR, f) !== todayFile)
    .sort();
  const prev = files.at(-1);
  if (!prev) return keys;
  try {
    const doc = JSON.parse(readFileSync(join(RADAR_DIR, prev), "utf-8")) as {
      items?: RadarItem[];
    };
    for (const it of doc.items ?? []) keys.add(itemKey(it));
    if (VERBOSE)
      console.error(`  prev digest ${prev}: ${keys.size} keys for dedup`);
  } catch (e) {
    if (VERBOSE)
      console.error(`  could not read prev digest ${prev}: ${(e as Error).message}`);
  }
  return keys;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

async function runSource(
  source: string,
  fn: (res: SourceResult) => Promise<RadarItem[]>,
): Promise<{ result: SourceResult; items: RadarItem[] }> {
  const result: SourceResult = {
    source,
    ok: false,
    items_raw: 0,
    items_relevant: 0,
  };
  try {
    const items = await fn(result);
    result.ok = true;
    result.items_relevant = items.length;
    if (VERBOSE)
      console.error(
        `  [ok]   ${source}: ${result.items_raw} raw -> ${items.length} relevant`,
      );
    return { result, items };
  } catch (e) {
    result.error = (e as Error).message;
    if (VERBOSE) console.error(`  [fail] ${source}: ${result.error}`);
    return { result, items: [] };
  }
}

async function main(): Promise<void> {
  const generatedAt = new Date().toISOString();
  const runDate = generatedAt.slice(0, 10);

  console.error("=== sync-radar.ts (early-warning radar) ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"} | run_date: ${runDate}`);

  const collectors: {
    source: string;
    fn: (res: SourceResult) => Promise<RadarItem[]>;
  }[] = [
    { source: "hackernews", fn: collectHackerNews },
    {
      source: "embracethered",
      fn: (r) =>
        collectFeed(
          r,
          "https://embracethered.com/blog/index.xml",
          "embracethered",
          true,
          "agent-security-blog",
        ),
    },
    {
      source: "simonwillison",
      fn: (r) =>
        collectFeed(
          r,
          "https://simonwillison.net/tags/prompt-injection.atom",
          "simonwillison",
          true,
          "prompt-injection",
        ),
    },
    {
      source: "zdi",
      fn: (r) =>
        collectFeed(
          r,
          "https://www.zerodayinitiative.com/blog?format=rss",
          "zdi",
          false,
          "zdi",
        ),
    },
    { source: "lobsters", fn: collectLobsters },
  ];

  const sourcesPolled: SourceResult[] = [];
  let allItems: RadarItem[] = [];

  for (const c of collectors) {
    const { result, items } = await runSource(c.source, c.fn);
    sourcesPolled.push(result);
    allItems.push(...items);
  }

  const okCount = sourcesPolled.filter((s) => s.ok).length;

  // No data path: every source failed -> recoverable exit 2.
  if (okCount === 0) {
    const digest = {
      generated_at: generatedAt,
      run_date: runDate,
      sources_polled: sourcesPolled,
      items: [],
    };
    console.log(JSON.stringify(digest, null, 2));
    console.log(
      `::radar-summary::${JSON.stringify({
        sources_polled: sourcesPolled.length,
        items_total: 0,
        items_relevant: 0,
        new_since_last: 0,
      })}`,
    );
    console.error(
      "No data path: every source failed (network / non-200). Recoverable -- retry later.",
    );
    process.exit(2);
  }

  // Cross-source dedup within this run (normalized url / title).
  const seen = new Set<string>();
  const deduped: RadarItem[] = [];
  for (const it of allItems) {
    const k = itemKey(it);
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(it);
  }

  // Dedup against previous digest -> "new since last".
  const todayFile = join(RADAR_DIR, `radar-${runDate}.json`);
  const prevKeys = loadPreviousKeys(todayFile);
  const newItems = deduped.filter((it) => !prevKeys.has(itemKey(it)));
  const newSinceLast = newItems.length;

  // Sort newest first (undated items last), then cap with --limit.
  deduped.sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""));
  const items = deduped.slice(0, LIMIT);

  const digest = {
    generated_at: generatedAt,
    run_date: runDate,
    sources_polled: sourcesPolled,
    items,
  };

  if (WRITE) {
    if (!existsSync(RADAR_DIR)) mkdirSync(RADAR_DIR, { recursive: true });
    const json = JSON.stringify(digest, null, 2);
    writeFileSync(todayFile, json, "utf-8");
    writeFileSync(join(RADAR_DIR, "latest.json"), json, "utf-8");
    console.error(`  wrote ${todayFile.replace(REPO_ROOT + "/", "")}`);
    console.error(`  wrote data/radar/latest.json`);
  } else {
    console.error(
      `  [dry-run] would write data/radar/radar-${runDate}.json (+ latest.json) with ${items.length} items`,
    );
  }

  // Human-readable summary.
  console.log(
    JSON.stringify(
      {
        run_date: runDate,
        mode: WRITE ? "WRITE" : "dry-run",
        sources_polled: sourcesPolled,
        items_relevant_total: deduped.length,
        items_in_digest: items.length,
        new_since_last: newSinceLast,
        sample: items.slice(0, 5).map((i) => ({
          source: i.source,
          title: i.title,
          matched: i.matched_keywords,
        })),
      },
      null,
      2,
    ),
  );

  console.log(
    `::radar-summary::${JSON.stringify({
      sources_polled: okCount,
      items_total: deduped.length,
      items_relevant: deduped.length,
      new_since_last: newSinceLast,
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
